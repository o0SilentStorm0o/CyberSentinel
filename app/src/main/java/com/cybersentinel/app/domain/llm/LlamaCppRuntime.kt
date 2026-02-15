package com.cybersentinel.app.domain.llm

import android.os.Build
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock

/**
 * LlamaCppRuntime — production LlmRuntime backed by llama.cpp via JNI.
 *
 * C2-2.5 hardening (review fixes):
 *  - **Real timeout**: ExecutorService + Future.get(timeout) + cooperative JNI cancel flag.
 *    When timeout fires, we call nativeCancelInference() so the native decode loop actually
 *    stops generating — no phantom CPU burn.
 *  - **Deterministic sampling**: temperature=0, greedy argmax in JNI. No top-p, no randomness.
 *    Maximizes schema compliance for slots-only JSON output.
 *  - **JSON stop sequence**: JNI stops when braces are balanced (closed JSON object).
 *  - **Token count from JNI**: native returns "TOKEN_COUNT|TTFT_MS|text", parsed here.
 *  - **LlamaSession struct in C++**: model + context + cancel_flag + poisoned owned atomically.
 *  - **n_batch tier-aware**: 128 default, configurable at create() time.
 *
 * C2-2.6 hardening:
 *  - **Single-flight inference**: tryLock fails immediately → BUSY error (no queue).
 *  - **Timeout cooldown**: 100ms wait after cancel before returning, lets native loop stop.
 *  - **TTFT from JNI**: real time-to-first-token measured in native decode loop.
 *  - **Strict JNI prefix guard**: token count prefix must be ≤6 digits.
 *  - **Poisoned handle guard in C++**: after unload, all JNI calls return error.
 *
 * C2-2.7 hardening:
 *  - **Generational handle registry in C++**: eliminates use-after-free completely.
 *    Kotlin holds uint64 handle, JNI looks up via global map + shared_ptr.
 *    nativeUnload erases handle; shared_ptr defers free until in-flight inference finishes.
 *  - **TTFT validation**: TTFT > 120s treated as invalid → null (prevents garbage metrics).
 *  - **Token count validation**: tokenCount > MAX_TOKEN_COUNT treated as invalid → fallback.
 *
 * C2-2.8 hardening:
 *  - **Running guard in C++**: atomic `running` flag + RAII InferenceGuard.
 *    nativeUnload waits up to 300ms for running==false before freeing ctx/model.
 *    If timeout, ctx/model are NOT freed (leak beats crash).
 *  - **Structured JNI errors**: all C++ errors use "ERR|CODE|message" format.
 *    Kotlin rejects ERR| prefix before parsing metrics. Eliminates silent degradation.
 *  - **Null tokenCount fallback**: unparseable JNI output returns tokenCount=null
 *    (not 0). null = "we don't know". Aligns with InferenceResult three-state semantics.
 *
 * Contract:
 *  - ARM64-only: `isAvailable` returns false on non-arm64 devices.
 *  - Single-flight: only one inference at a time; concurrent calls get BUSY error.
 *  - Idempotent shutdown: safe to call multiple times.
 *  - Native handle lifecycle: `nativeHandle` is set on load, zeroed on shutdown.
 *
 * JNI library: `libllama_jni.so` (built via CMake + NDK, statically linked ggml).
 *
 * Memory model:
 *  - Model weights live in native heap (mmap'd GGUF).
 *  - KV cache is allocated inside llama.cpp context (bounded by n_ctx).
 *  - Prompt + output strings cross JNI as UTF-8 byte arrays.
 *
 * Threading:
 *  - `runInference()` acquires inferenceLock.tryLock() → single-flight.
 *  - `shutdown()` acquires inferenceLock → safe concurrent access.
 *  - Native inference runs on a dedicated single-thread executor.
 */
class LlamaCppRuntime private constructor(
    private val modelPath: String,
    private val contextSize: Int,
    private val nThreads: Int,
    private val runtimeVersion: String
) : LlmRuntime {

    // ── JNI native handle (pointer to LlamaSession struct) ──
    @Volatile
    private var nativeHandle: Long = 0L

    // ── Inference lock: ensures single inference at a time ──
    private val inferenceLock = ReentrantLock()

    // ── Dedicated executor for inference — Future.get(timeout) for real timeout ──
    private val inferenceExecutor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "llama-inference").apply { isDaemon = true }
    }

    // ── Current in-flight future for cancel support ──
    @Volatile
    private var currentFuture: Future<String?>? = null

    // ══════════════════════════════════════════════════════════
    //  LlmRuntime interface
    // ══════════════════════════════════════════════════════════

    override val runtimeId: String
        get() = "llama_cpp_${runtimeVersion}_arm64"

    override val isAvailable: Boolean
        get() = nativeHandle != 0L && isArm64Device()

    override fun runInference(prompt: String, config: InferenceConfig): InferenceResult {
        if (!isAvailable) {
            return InferenceResult.failure("Runtime not available (handle=$nativeHandle, arm64=${isArm64Device()})")
        }

        // C2-2.6: single-flight — if another inference is running, return BUSY immediately
        val acquired = inferenceLock.tryLock()
        if (!acquired) {
            return InferenceResult.failure("Inference busy: another call is in progress (single-flight)")
        }

        val startTime = System.currentTimeMillis()

        try {
            val handle = nativeHandle
            if (handle == 0L) {
                return InferenceResult.failure("Model unloaded during inference setup")
            }

            // Submit JNI call to dedicated thread — we can timeout with Future.get()
            val future = inferenceExecutor.submit(Callable<String?> {
                nativeRunInference(
                    handle = handle,
                    prompt = prompt,
                    maxTokens = config.maxNewTokens,
                    temperature = 0f,  // C2-2.5: deterministic greedy — ignore config.temperature
                    topP = 1.0f,       // C2-2.5: no top-p filtering — greedy argmax in JNI
                    timeoutMs = config.timeoutMs
                )
            })
            currentFuture = future

            // Wait with real timeout — if it fires, we cancel the native side too
            val rawOutput: String?
            try {
                rawOutput = future.get(config.timeoutMs + TIMEOUT_GRACE_MS, TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                // Real timeout: cancel the future AND signal native cancel flag
                future.cancel(true)
                nativeCancelInferenceSafe(handle)
                // C2-2.6: cooldown — let native loop stop before returning
                // Without this, a quick retry could hit the lock while native is still winding down
                Thread.sleep(CANCEL_COOLDOWN_MS)
                val elapsed = System.currentTimeMillis() - startTime
                return InferenceResult.failure("Timeout: inference exceeded ${config.timeoutMs}ms (native cancelled)", elapsed)
            } catch (e: CancellationException) {
                val elapsed = System.currentTimeMillis() - startTime
                return InferenceResult.failure("Inference cancelled", elapsed)
            } catch (e: Exception) {
                val elapsed = System.currentTimeMillis() - startTime
                return InferenceResult.failure("Inference exception: ${e.cause?.message ?: e.message}", elapsed)
            } finally {
                currentFuture = null
            }

            val totalTime = System.currentTimeMillis() - startTime

            if (rawOutput == null || rawOutput.isEmpty()) {
                return InferenceResult.failure("Empty output from native inference", totalTime)
            }

            // C2-2.8: structured JNI error format: "ERR|CODE|message"
            // Also keep backward compat with legacy "ERROR:" prefix
            if (rawOutput.startsWith("ERR|") || rawOutput.startsWith("ERROR:")) {
                return InferenceResult.failure(rawOutput, totalTime)
            }

            // Parse "TOKEN_COUNT|TTFT_MS|output_text" format from JNI (C2-2.6)
            val parsed = parseJniOutput(rawOutput)

            return InferenceResult.success(
                rawOutput = parsed.text,
                timeToFirstTokenMs = parsed.ttftMs,
                totalTimeMs = totalTime,
                tokensGenerated = parsed.tokenCount
            )
        } catch (e: UnsatisfiedLinkError) {
            val elapsed = System.currentTimeMillis() - startTime
            return InferenceResult.failure("JNI link error: ${e.message}", elapsed)
        } catch (e: Exception) {
            val elapsed = System.currentTimeMillis() - startTime
            return InferenceResult.failure("Inference exception: ${e.message}", elapsed)
        } finally {
            inferenceLock.unlock()
        }
    }

    override fun shutdown() {
        inferenceLock.lock()
        try {
            // Cancel any in-flight inference
            currentFuture?.cancel(true)
            currentFuture = null

            val handle = nativeHandle
            if (handle != 0L) {
                nativeHandle = 0L
                try {
                    nativeUnload(handle)
                } catch (_: Exception) {
                    // Best-effort cleanup
                }
            }

            // Shutdown executor (don't await — daemon thread will die with JVM)
            inferenceExecutor.shutdownNow()
        } finally {
            inferenceLock.unlock()
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Cancel support
    // ══════════════════════════════════════════════════════════

    /**
     * Request cancellation of the in-flight inference.
     * Sets the cooperative cancel flag in native code AND cancels the Future.
     */
    fun cancelInference() {
        currentFuture?.cancel(true)
        nativeCancelInferenceSafe(nativeHandle)
    }

    /** Safe wrapper — catches UnsatisfiedLinkError in unit tests */
    private fun nativeCancelInferenceSafe(handle: Long) {
        if (handle == 0L) return
        try {
            nativeCancelInference(handle)
        } catch (_: UnsatisfiedLinkError) {
            // Expected in unit tests — no native lib
        }
    }

    // ══════════════════════════════════════════════════════════
    //  JNI output parsing
    // ══════════════════════════════════════════════════════════

    /**
     * Parsed JNI output — structured result from "TOKEN_COUNT|TTFT_MS|text".
     *
     * C2-2.8: tokenCount is Int? — null means "we don't know" (unparseable JNI output
     * or error string). 0 means "inference ran but produced no usable tokens".
     */
    internal data class JniParsedOutput(
        val text: String,
        val tokenCount: Int?,
        val ttftMs: Long?
    )

    /**
     * Parse JNI return format: "TOKEN_COUNT|TTFT_MS|output_text" (C2-2.6 extended)
     *
     * Falls back to C2-2.5 format "TOKEN_COUNT|text" if only one '|' found.
     * Falls back to raw text if format doesn't match.
     *
     * C2-2.6 strict prefix guard: token count + ttft prefixes must be ≤6 chars
     * and all-digits. Prevents garbage from being parsed as metrics.
     *
     * C2-2.7 validation:
     *  - Token count > MAX_TOKEN_COUNT → treat as corrupt, fallback to raw text.
     *  - TTFT > MAX_TTFT_MS → treat as measurement error, set ttftMs to null.
     *
     * C2-2.8 changes:
     *  - ERR| / ERROR: prefix → rejected immediately, returns (raw, null, null).
     *  - Fallback tokenCount is null (was 0). null = "we don't know".
     *    0 means "inference ran but produced nothing usable".
     */
    internal fun parseJniOutput(raw: String): JniParsedOutput {
        // C2-2.8: structured error prefix — never parse as metrics
        if (raw.startsWith("ERR|") || raw.startsWith("ERROR:")) {
            return JniParsedOutput(raw, null, null)
        }

        val firstPipe = raw.indexOf('|')
        if (firstPipe <= 0 || firstPipe > MAX_PREFIX_LEN) {
            return JniParsedOutput(raw, null, null)
        }

        val countStr = raw.substring(0, firstPipe)
        if (!countStr.all { it.isDigit() }) {
            return JniParsedOutput(raw, null, null)
        }

        val tokenCount = countStr.toIntOrNull()
            ?: return JniParsedOutput(raw, null, null)

        // C2-2.7: reject implausibly large token counts
        if (tokenCount > MAX_TOKEN_COUNT) {
            return JniParsedOutput(raw, null, null)
        }

        // Try C2-2.6 extended format: "TOKEN_COUNT|TTFT_MS|text"
        val afterFirst = raw.substring(firstPipe + 1)
        val secondPipe = afterFirst.indexOf('|')
        if (secondPipe > 0 && secondPipe <= MAX_PREFIX_LEN) {
            val ttftStr = afterFirst.substring(0, secondPipe)
            if (ttftStr.all { it.isDigit() }) {
                val ttftRaw = ttftStr.toLongOrNull()
                // C2-2.7: clamp implausibly large TTFT to null (measurement error)
                val ttftMs = if (ttftRaw != null && ttftRaw <= MAX_TTFT_MS) ttftRaw else null
                val text = afterFirst.substring(secondPipe + 1)
                return JniParsedOutput(text, tokenCount, ttftMs)
            }
        }

        // Fallback to C2-2.5 format: "TOKEN_COUNT|text"
        return JniParsedOutput(afterFirst, tokenCount, null)
    }

    // ══════════════════════════════════════════════════════════
    //  JNI native methods (implemented in llama_jni.cpp)
    // ══════════════════════════════════════════════════════════

    /**
     * Load a GGUF model from disk into native memory.
     * Creates a LlamaSession struct in C++ with model + context + cancel flag.
     *
     * @param modelPath Absolute path to the .gguf file
     * @param contextSize Max context length (n_ctx). Keep ≤ 2048 for slots-only.
     * @param nThreads Number of CPU threads for inference.
     * @return Native handle (pointer to LlamaSession), or 0 on failure.
     */
    private external fun nativeLoadModel(
        modelPath: String,
        contextSize: Int,
        nThreads: Int
    ): Long

    /**
     * Run inference on a loaded model. Deterministic greedy decode.
     *
     * Returns "TOKEN_COUNT|TTFT_MS|output_text" format (C2-2.6 extended).
     * Checks cooperative cancel flag every token in the decode loop.
     * Stops on: EOS, maxTokens, timeout, cancel flag, or closed JSON object.
     *
     * @param handle Native session handle from nativeLoadModel
     * @param prompt Full prompt string (UTF-8)
     * @param maxTokens Maximum new tokens to generate
     * @param temperature Ignored in C2-2.5+ (always greedy), kept for API compat
     * @param topP Ignored in C2-2.5+ (always greedy), kept for API compat
     * @param timeoutMs Hard timeout in milliseconds (native side, belt+suspenders)
     * @return "TOKEN_COUNT|TTFT_MS|text", or "ERROR:..." on failure, or null on OOM
     */
    private external fun nativeRunInference(
        handle: Long,
        prompt: String,
        maxTokens: Int,
        temperature: Float,
        topP: Float,
        timeoutMs: Long
    ): String?

    /**
     * Unload model and free all native resources (LlamaSession struct).
     * Sets poisoned flag first (C2-2.6), then cancel flag, so any in-flight inference stops.
     * Nullifies model+ctx before delete for stale-handle safety.
     *
     * @param handle Native session handle
     */
    private external fun nativeUnload(handle: Long)

    /**
     * Set the cooperative cancel flag on the native session.
     * The decode loop checks this flag every token and exits when set.
     * This is what makes timeout a REAL timeout, not just cosmetic.
     *
     * @param handle Native session handle
     */
    private external fun nativeCancelInference(handle: Long)

    // ══════════════════════════════════════════════════════════
    //  Factory + companion
    // ══════════════════════════════════════════════════════════

    companion object {
        private const val JNI_LIB_NAME = "llama_jni"
        private const val DEFAULT_CONTEXT_SIZE = 2048
        private const val DEFAULT_N_THREADS = 4
        private const val RUNTIME_VERSION = "v1"

        /**
         * Grace period beyond config.timeoutMs for Future.get().
         * The native side has its own timeout check; this is belt+suspenders.
         * If native doesn't exit within timeout+grace, Future.get throws TimeoutException
         * and we call nativeCancelInference() to force-stop the decode loop.
         */
        internal const val TIMEOUT_GRACE_MS = 500L

        /**
         * C2-2.6: Cooldown after cancel — lets the native decode loop stop before
         * we release the inference lock. Without this, a quick retry could overlap
         * with the winding-down native thread.
         */
        internal const val CANCEL_COOLDOWN_MS = 100L

        /**
         * C2-2.6: Maximum length for numeric prefixes in JNI output format.
         * Token count and TTFT must be ≤ 6 digits (up to 999999).
         * Prevents garbage from being parsed as metrics.
         */
        private const val MAX_PREFIX_LEN = 6

        /**
         * C2-2.7: Maximum plausible TTFT value in milliseconds.
         * If JNI reports TTFT > 120 seconds, treat as measurement error → null.
         * 120s is well beyond any reasonable first-token latency on mobile.
         */
        internal const val MAX_TTFT_MS = 120_000L

        /**
         * C2-2.7: Maximum plausible token count from a single inference.
         * If JNI reports more tokens than this, treat as corrupt output → fallback.
         * Matches MAX_PREFIX_LEN (6 digits = 999999).
         */
        internal const val MAX_TOKEN_COUNT = 999_999

        @Volatile
        private var libraryLoaded = false

        /**
         * Check if the current device has arm64 ABI support.
         * LLM inference is restricted to arm64 for performance and memory safety.
         */
        fun isArm64Device(): Boolean {
            return try {
                Build.SUPPORTED_ABIS?.any { it == "arm64-v8a" } ?: false
            } catch (_: Exception) {
                false
            }
        }

        /**
         * Load the JNI library. Safe to call multiple times.
         *
         * @return true if the library is loaded, false on failure
         */
        fun loadLibrary(): Boolean {
            if (libraryLoaded) return true
            return try {
                System.loadLibrary(JNI_LIB_NAME)
                libraryLoaded = true
                true
            } catch (_: UnsatisfiedLinkError) {
                false
            }
        }

        /**
         * Create and initialize a LlamaCppRuntime.
         *
         * Steps:
         *  1. Check arm64 ABI
         *  2. Load JNI library
         *  3. Load model via native call
         *  4. Return ready runtime (or null on failure)
         *
         * @param modelPath Absolute path to the .gguf model file
         * @param contextSize Context window size (tokens). Default 2048.
         * @param nThreads CPU threads for inference. Default 4.
         * @return LlamaCppRuntime ready for inference, or null on failure
         */
        fun create(
            modelPath: String,
            contextSize: Int = DEFAULT_CONTEXT_SIZE,
            nThreads: Int = DEFAULT_N_THREADS
        ): LlamaCppRuntime? {
            // Gate 1: ARM64 only
            if (!isArm64Device()) return null

            // Gate 2: Load native library
            if (!loadLibrary()) return null

            // Gate 3: Instantiate and load model
            val runtime = LlamaCppRuntime(
                modelPath = modelPath,
                contextSize = contextSize,
                nThreads = nThreads,
                runtimeVersion = RUNTIME_VERSION
            )

            val handle = try {
                runtime.nativeLoadModel(modelPath, contextSize, nThreads)
            } catch (_: Exception) {
                return null
            }

            if (handle == 0L) return null

            runtime.nativeHandle = handle
            return runtime
        }

        /**
         * Create a runtime instance without loading a model (for testing ABI gate behavior).
         * The instance will have nativeHandle=0 and isAvailable=false.
         */
        internal fun createUnloaded(): LlamaCppRuntime {
            return LlamaCppRuntime(
                modelPath = "",
                contextSize = DEFAULT_CONTEXT_SIZE,
                nThreads = DEFAULT_N_THREADS,
                runtimeVersion = RUNTIME_VERSION
            )
        }
    }
}
