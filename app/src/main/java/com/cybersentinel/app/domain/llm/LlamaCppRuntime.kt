package com.cybersentinel.app.domain.llm

import android.os.Build
import java.util.concurrent.locks.ReentrantLock

/**
 * LlamaCppRuntime — production LlmRuntime backed by llama.cpp via JNI.
 *
 * Contract:
 *  - ARM64-only: `isAvailable` returns false on non-arm64 devices.
 *  - Single-inference lock: only one inference at a time (ReentrantLock).
 *  - Idempotent shutdown: safe to call multiple times.
 *  - Native handle lifecycle: `nativeHandle` is set on load, zeroed on shutdown.
 *  - Timeout: monitored from the JVM side; native code checks a cancel flag.
 *
 * JNI library: `libllama_jni.so` (built via CMake + NDK, statically linked ggml).
 *
 * Memory model:
 *  - Model weights live in native heap (mmap'd GGUF).
 *  - KV cache is allocated inside llama.cpp context (bounded by n_ctx).
 *  - Prompt + output strings cross JNI as UTF-8 byte arrays.
 *
 * Threading:
 *  - `runInference()` acquires inferenceLock → only one call at a time.
 *  - `shutdown()` acquires inferenceLock → safe concurrent access.
 */
class LlamaCppRuntime private constructor(
    private val modelPath: String,
    private val contextSize: Int,
    private val nThreads: Int,
    private val runtimeVersion: String
) : LlmRuntime {

    // ── JNI native handle ──
    @Volatile
    private var nativeHandle: Long = 0L

    // ── Inference lock: ensures single inference at a time ──
    private val inferenceLock = ReentrantLock()

    // ── Cancel flag for in-flight inference ──
    @Volatile
    private var cancelRequested = false

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

        val acquired = inferenceLock.tryLock()
        if (!acquired) {
            return InferenceResult.failure("Inference already in progress (single-threaded lock)")
        }

        cancelRequested = false
        val startTime = System.currentTimeMillis()

        try {
            val handle = nativeHandle
            if (handle == 0L) {
                return InferenceResult.failure("Model unloaded during inference setup")
            }

            // JNI call — blocking, runs on caller's thread
            val rawOutput = nativeRunInference(
                handle = handle,
                prompt = prompt,
                maxTokens = config.maxNewTokens,
                temperature = config.temperature,
                topP = config.topP,
                timeoutMs = config.timeoutMs
            )

            val totalTime = System.currentTimeMillis() - startTime

            // Check timeout on JVM side (belt + suspenders with native timeout)
            if (totalTime > config.timeoutMs) {
                return InferenceResult.failure("Timeout exceeded (${totalTime}ms > ${config.timeoutMs}ms)", totalTime)
            }

            if (rawOutput == null || rawOutput.isEmpty()) {
                return InferenceResult.failure("Empty output from native inference", totalTime)
            }

            if (rawOutput.startsWith("ERROR:")) {
                return InferenceResult.failure(rawOutput, totalTime)
            }

            val estimatedTokens = (rawOutput.length / 4).coerceAtLeast(1)
            return InferenceResult.success(
                rawOutput = rawOutput,
                timeToFirstTokenMs = (totalTime * 0.3).toLong(),  // estimate; native doesn't report TTFB yet
                totalTimeMs = totalTime,
                tokensGenerated = estimatedTokens
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
            val handle = nativeHandle
            if (handle != 0L) {
                nativeHandle = 0L
                try {
                    nativeUnload(handle)
                } catch (_: Exception) {
                    // Best-effort cleanup
                }
            }
        } finally {
            inferenceLock.unlock()
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Cancel support
    // ══════════════════════════════════════════════════════════

    /**
     * Request cancellation of the in-flight inference.
     * The native code checks this flag periodically.
     */
    fun cancelInference() {
        cancelRequested = true
    }

    // ══════════════════════════════════════════════════════════
    //  JNI native methods (implemented in llama_jni.cpp)
    // ══════════════════════════════════════════════════════════

    /**
     * Load a GGUF model from disk into native memory.
     *
     * @param modelPath Absolute path to the .gguf file
     * @param contextSize Max context length (n_ctx). Keep ≤ 2048 for slots-only.
     * @param nThreads Number of CPU threads for inference.
     * @return Native handle (pointer), or 0 on failure.
     */
    private external fun nativeLoadModel(
        modelPath: String,
        contextSize: Int,
        nThreads: Int
    ): Long

    /**
     * Run inference on a loaded model.
     *
     * @param handle Native model handle from nativeLoadModel
     * @param prompt Full prompt string (UTF-8)
     * @param maxTokens Maximum new tokens to generate
     * @param temperature Sampling temperature
     * @param topP Top-p nucleus sampling threshold
     * @param timeoutMs Hard timeout in milliseconds (native side)
     * @return Generated text, or "ERROR:..." on failure, or null on OOM
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
     * Unload model and free all native resources.
     *
     * @param handle Native model handle
     */
    private external fun nativeUnload(handle: Long)

    // ══════════════════════════════════════════════════════════
    //  Factory + companion
    // ══════════════════════════════════════════════════════════

    companion object {
        private const val JNI_LIB_NAME = "llama_jni"
        private const val DEFAULT_CONTEXT_SIZE = 2048
        private const val DEFAULT_N_THREADS = 4
        private const val RUNTIME_VERSION = "v1"

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
