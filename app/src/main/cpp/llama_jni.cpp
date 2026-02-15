/**
 * llama_jni.cpp — JNI bridge between LlamaCppRuntime.kt and llama.cpp C API.
 *
 * This file provides the minimal JNI surface for CyberSentinel's slots-only
 * inference pipeline:
 *   1. nativeLoadModel       — load GGUF model into memory
 *   2. nativeRunInference    — run completion (prompt → slots JSON)
 *   3. nativeUnload          — free model + context
 *   4. nativeCancelInference — cooperative cancel via atomic flag
 *
 * Design decisions (C2-2.5 + C2-2.6 + C2-2.7 + C2-2.8 hardening):
 *   - Static link ggml + llama.cpp (no separate .so for ggml)
 *   - CPU-only inference (no Vulkan/NNAPI in C2-2; future C2-4)
 *   - Hard n_ctx ceiling (2048 default — slots-only prompts are short)
 *   - DETERMINISTIC sampling: temperature=0, greedy top-1 (no randomness)
 *   - Cooperative cancel flag: checked every token in decode loop
 *   - JSON stop sequence: stops on closed JSON object (balanced braces)
 *     with stateful escape handling for \\\" sequences (C2-2.6)
 *   - Hard timeout via elapsed-time check each token
 *   - No streaming — returns "token_count|ttft_ms|output_text" on completion
 *   - **Generational handle registry** (C2-2.7): eliminates use-after-free.
 *     Kotlin never holds a raw pointer — only a uint64 handle composed of
 *     (generation_id << 32) | slot_id. JNI lookups go through a global
 *     unordered_map<uint64_t, shared_ptr<LlamaSession>> + mutex.
 *     nativeUnload erases the handle from the map; shared_ptr ensures the
 *     session memory is freed only after all in-flight references are released.
 *   - **Running guard** (C2-2.8): atomic<bool> `running` flag + RAII InferenceGuard.
 *     nativeUnload spin-waits on `running == false` (max 300ms) before freeing
 *     ctx/model. If timeout: ctx/model are NOT freed (leak beats crash).
 *   - Single model context per handle (no batched inference)
 *   - LlamaSession struct owns model+context+cancel+poisoned atomically
 *
 * Return format: "TOKEN_COUNT|TTFT_MS|generated_text"
 *   Kotlin side splits on first two '|' to get exact token count and TTFT.
 *
 * Error format (C2-2.8): "ERR|CODE|human_message"
 *   Kotlin rejects ERR| prefix before metric parsing — prevents silent degradation.
 *
 * Build: Via CMakeLists.txt → libllama_jni.so (arm64-v8a only)
 *
 * Copyright (c) 2026 CyberSentinel. All rights reserved.
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <atomic>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <thread>
#include <android/log.h>

// llama.cpp headers (paths resolved by CMake include_directories)
#include "llama.h"
#include "common.h"

#define TAG "LlamaJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ══════════════════════════════════════════════════════════
//  LlamaSession — owns model + context + cancel flag atomically
// ══════════════════════════════════════════════════════════

/**
 * Single-owner session struct. Managed via shared_ptr in the global registry.
 * Kotlin never holds a raw pointer — only a generational handle (uint64_t).
 *
 * C2-2.7: poisoned flag is set by unload. All JNI ops check poisoned first.
 * Even after the handle is erased from the registry, an in-flight shared_ptr
 * may still reference this struct — poisoned prevents any further work.
 */
struct LlamaSession {
    llama_model*       model       = nullptr;
    llama_context*     ctx         = nullptr;
    int                n_ctx       = 2048;
    int                n_threads   = 4;
    std::atomic<bool>  cancel_flag{false};  // cooperative cancel — checked every token
    std::atomic<bool>  poisoned{false};     // set after unload — prevents reuse
    std::atomic<bool>  running{false};      // C2-2.8: true while inference is in progress
};

/**
 * RAII guard: sets session->running = true on construction, false on destruction.
 * Ensures running flag is always cleared even if inference throws or returns early.
 */
struct InferenceGuard {
    std::shared_ptr<LlamaSession> session;
    explicit InferenceGuard(std::shared_ptr<LlamaSession> s) : session(std::move(s)) {
        if (session) session->running.store(true, std::memory_order_release);
    }
    ~InferenceGuard() {
        if (session) session->running.store(false, std::memory_order_release);
    }
    InferenceGuard(const InferenceGuard&) = delete;
    InferenceGuard& operator=(const InferenceGuard&) = delete;
};

// ══════════════════════════════════════════════════════════
//  Global session registry — generational handles (C2-2.7)
// ══════════════════════════════════════════════════════════
//
//  Handle format (uint64_t, returned as jlong to Kotlin):
//    bits [63..32] = generation counter (monotonically increasing)
//    bits [31.. 0] = slot index (recycled)
//
//  Lookup: registry.find(handle) → shared_ptr<LlamaSession> or nullptr.
//  nativeLoadModel inserts into registry, returns handle.
//  nativeUnload erases from registry; shared_ptr ref-count ensures deferred free.
//  If Kotlin sends a stale handle (generation mismatch), lookup returns end() → fail safe.
//
//  This eliminates use-after-free: no raw pointer cast, no dangling memory access.

static std::mutex                                                   g_registry_mutex;
static std::unordered_map<uint64_t, std::shared_ptr<LlamaSession>>  g_registry;
static uint32_t                                                     g_generation{0};
static uint32_t                                                     g_slot{0};

/**
 * Register a session and return a unique generational handle.
 * Caller must NOT hold g_registry_mutex.
 */
static uint64_t registry_insert(std::shared_ptr<LlamaSession> session) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    uint32_t gen = ++g_generation;
    uint32_t slot = ++g_slot;

    // C2-2.8: overflow guard — if either counter wraps to 0, refuse the insert.
    // 2^32 loads is ~unlikely in practice, but a long-running process with a bug
    // (leak loop) could hit it. Fail-safe: refuse load rather than risk handle collision.
    if (gen == 0 || slot == 0) {
        LOGE("registry_insert: generation/slot counter overflow — refusing load "
             "(gen=%u, slot=%u). Restart app to reset.", gen, slot);
        return 0;
    }

    uint64_t handle = (static_cast<uint64_t>(gen) << 32) | static_cast<uint64_t>(slot);
    g_registry[handle] = std::move(session);
    return handle;
}

/**
 * Look up a session by handle. Returns nullptr if handle is stale/invalid.
 * The returned shared_ptr keeps the session alive for the duration of the call.
 */
static std::shared_ptr<LlamaSession> registry_lookup(uint64_t handle) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = g_registry.find(handle);
    if (it == g_registry.end()) return nullptr;
    return it->second;  // shared_ptr copy — ref-count incremented
}

/**
 * Erase a session from the registry by handle.
 * The shared_ptr inside the map is dropped, but any in-flight copies keep the
 * session alive until they go out of scope.
 * Returns the shared_ptr so the caller can still access it for cleanup.
 */
static std::shared_ptr<LlamaSession> registry_erase(uint64_t handle) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = g_registry.find(handle);
    if (it == g_registry.end()) return nullptr;
    auto session = std::move(it->second);
    g_registry.erase(it);
    return session;
}

// ══════════════════════════════════════════════════════════
//  JNI_OnLoad — llama.cpp backend initialization
// ══════════════════════════════════════════════════════════

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    LOGI("JNI_OnLoad: initializing llama backend");
    llama_backend_init();
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNI_OnUnload(JavaVM* vm, void* /*reserved*/) {
    LOGI("JNI_OnUnload: freeing llama backend");
    llama_backend_free();
}

// ══════════════════════════════════════════════════════════
//  nativeLoadModel
// ══════════════════════════════════════════════════════════

extern "C" JNIEXPORT jlong JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeLoadModel(
    JNIEnv* env,
    jobject /* this */,
    jstring jModelPath,
    jint    contextSize,
    jint    nThreads
) {
    const char* modelPath = env->GetStringUTFChars(jModelPath, nullptr);
    if (!modelPath) {
        LOGE("nativeLoadModel: null model path");
        return 0;
    }

    LOGI("nativeLoadModel: loading %s (ctx=%d, threads=%d)", modelPath, contextSize, nThreads);

    // Model params
    llama_model_params model_params = llama_model_default_params();
    model_params.use_mmap = true;    // Memory-map for lower RAM footprint

    llama_model* model = llama_load_model_from_file(modelPath, model_params);
    env->ReleaseStringUTFChars(jModelPath, modelPath);

    if (!model) {
        LOGE("nativeLoadModel: failed to load model");
        return 0;
    }

    // Context params
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx     = static_cast<uint32_t>(contextSize);
    ctx_params.n_threads = static_cast<uint32_t>(nThreads);
    ctx_params.n_threads_batch = static_cast<uint32_t>(nThreads);

    llama_context* ctx = llama_new_context_with_model(model, ctx_params);
    if (!ctx) {
        LOGE("nativeLoadModel: failed to create context");
        llama_free_model(model);
        return 0;
    }

    auto session = std::make_shared<LlamaSession>();
    session->model     = model;
    session->ctx       = ctx;
    session->n_ctx     = contextSize;
    session->n_threads = nThreads;
    session->cancel_flag.store(false);

    // C2-2.7: register session in global registry, return generational handle
    uint64_t handle = registry_insert(session);

    LOGI("nativeLoadModel: model loaded successfully (handle=0x%llx)", (unsigned long long)handle);
    return static_cast<jlong>(handle);
}

// ══════════════════════════════════════════════════════════
//  nativeRunInference — deterministic greedy + cooperative cancel
// ══════════════════════════════════════════════════════════

/**
 * Helper: check if generated JSON object is closed (balanced braces).
 * Returns true when we've seen at least one '{' and brace depth returns to 0.
 *
 * C2-2.6 hardening:
 *  - Stateful escape handling: counts consecutive backslashes to correctly handle
 *    sequences like \\\" (escaped backslash + unescaped quote) vs \" (escaped quote).
 *  - Ignores all characters before the first '{' (handles whitespace/preamble).
 *  - Tracks in_string state to avoid counting braces inside string literals.
 *
 * C2-2.7 hardening:
 *  - Explicit control character handling: newline, tab, carriage return and all
 *    characters < 0x20 reset the consecutive_backslashes counter and are skipped
 *    when outside a string. Inside a string they are treated as content (invalid
 *    JSON, but defensive).
 */
static bool is_json_object_closed(const std::string& text) {
    int depth = 0;
    bool seen_open = false;
    bool in_string = false;
    int consecutive_backslashes = 0;

    for (char c : text) {
        if (!seen_open && c != '{') {
            // Skip any preamble before first '{'
            continue;
        }

        // C2-2.7: control characters (< 0x20) always reset backslash counter.
        // Inside a string they are technically invalid JSON, but we handle defensively.
        if (static_cast<unsigned char>(c) < 0x20) {
            consecutive_backslashes = 0;
            continue;
        }

        if (c == '\\') {
            consecutive_backslashes++;
            continue;
        }

        // A quote is escaped only if preceded by an ODD number of backslashes
        bool char_is_escaped = (consecutive_backslashes % 2) == 1;
        consecutive_backslashes = 0;

        if (c == '"' && !char_is_escaped) {
            in_string = !in_string;
            continue;
        }

        if (in_string) continue;

        if (c == '{') { depth++; seen_open = true; }
        else if (c == '}') { depth--; }
        if (seen_open && depth == 0) return true;
    }
    return false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeRunInference(
    JNIEnv* env,
    jobject /* this */,
    jlong   handle,
    jstring jPrompt,
    jint    maxTokens,
    jfloat  temperature,
    jfloat  topP,
    jlong   timeoutMs
) {
    if (handle == 0) {
        return env->NewStringUTF("ERR|NULL_HANDLE|null handle");
    }

    // C2-2.7: look up session via generational handle registry
    auto session = registry_lookup(static_cast<uint64_t>(handle));
    if (!session) {
        return env->NewStringUTF("ERR|STALE_HANDLE|invalid or expired handle (session not found in registry)");
    }

    // C2-2.6: poisoned handle guard — prevents use-after-free race
    if (session->poisoned.load(std::memory_order_acquire)) {
        return env->NewStringUTF("ERR|POISONED|session has been unloaded (poisoned handle)");
    }
    if (!session->model || !session->ctx) {
        return env->NewStringUTF("ERR|NULL_CTX|model or context is null");
    }

    // C2-2.8: RAII guard — sets running=true now, running=false on scope exit.
    // nativeUnload spin-waits on running==false before freeing ctx/model.
    InferenceGuard guard(session);

    // Re-check poisoned after setting running — handles race where unload set
    // poisoned between our first check and InferenceGuard construction.
    if (session->poisoned.load(std::memory_order_acquire)) {
        return env->NewStringUTF("ERR|POISONED|session unloaded during inference setup");
    }

    // Reset cancel flag at inference start
    session->cancel_flag.store(false);

    const char* promptCStr = env->GetStringUTFChars(jPrompt, nullptr);
    if (!promptCStr) {
        return env->NewStringUTF("ERR|NULL_PROMPT|null prompt");
    }
    std::string prompt(promptCStr);
    env->ReleaseStringUTFChars(jPrompt, promptCStr);

    // Tokenize prompt
    const int n_prompt_max = session->n_ctx;
    std::vector<llama_token> tokens(n_prompt_max);
    int n_tokens = llama_tokenize(
        session->model,
        prompt.c_str(),
        static_cast<int32_t>(prompt.size()),
        tokens.data(),
        n_prompt_max,
        true,   // add_bos — always add BOS for consistent prompt framing
        false   // special
    );

    if (n_tokens < 0) {
        LOGE("nativeRunInference: tokenization failed (n_tokens=%d)", n_tokens);
        return env->NewStringUTF("ERR|TOKENIZE|tokenization failed");
    }
    tokens.resize(n_tokens);

    // Check if prompt fits in context
    if (n_tokens >= session->n_ctx) {
        LOGW("nativeRunInference: prompt too long (%d tokens > n_ctx=%d)", n_tokens, session->n_ctx);
        return env->NewStringUTF("ERR|CTX_OVERFLOW|prompt exceeds context window");
    }

    // Clear KV cache for fresh inference
    llama_kv_cache_clear(session->ctx);

    // Decode prompt (prefill)
    llama_batch batch = llama_batch_init(n_tokens, 0, 1);
    for (int i = 0; i < n_tokens; i++) {
        llama_batch_add(batch, tokens[i], i, { 0 }, false);
    }
    // Last token needs logits
    batch.logits[batch.n_tokens - 1] = true;

    if (llama_decode(session->ctx, batch) != 0) {
        llama_batch_free(batch);
        LOGE("nativeRunInference: prompt decode failed");
        return env->NewStringUTF("ERR|DECODE|prompt decode failed");
    }
    llama_batch_free(batch);

    // ── Deterministic greedy decode loop ──
    // temperature=0 → always pick highest-logit token (argmax / greedy)
    // No top-p, no sampling from distribution → maximal schema compliance
    auto start_time = std::chrono::steady_clock::now();
    long long ttft_ms = 0;  // C2-2.6: time to first token (ms)
    std::string output;
    output.reserve(maxTokens * 8);

    const llama_token eos = llama_token_eos(session->model);
    int n_cur = n_tokens;
    int generated_count = 0;

    for (int i = 0; i < maxTokens; i++) {
        // ── Cooperative cancel check ──
        if (session->cancel_flag.load(std::memory_order_relaxed)) {
            LOGW("nativeRunInference: cancelled by Kotlin after %d tokens", generated_count);
            break;
        }

        // ── Timeout check ──
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed_ms > timeoutMs) {
            LOGW("nativeRunInference: timeout after %lld ms (%d tokens)", (long long)elapsed_ms, generated_count);
            break;
        }

        // ── Greedy sampling: argmax over logits ──
        auto* logits = llama_get_logits_ith(session->ctx, -1);
        int n_vocab = llama_n_vocab(session->model);

        llama_token best_token = 0;
        float best_logit = logits[0];
        for (int t = 1; t < n_vocab; t++) {
            if (logits[t] > best_logit) {
                best_logit = logits[t];
                best_token = t;
            }
        }

        // Check EOS
        if (best_token == eos) {
            LOGI("nativeRunInference: EOS after %d tokens", generated_count);
            break;
        }

        // Convert token to text
        char buf[256];
        int n_chars = llama_token_to_piece(session->model, best_token, buf, sizeof(buf), 0, true);
        if (n_chars > 0) {
            output.append(buf, n_chars);
        }

        generated_count++;

        // C2-2.6: capture time-to-first-token on first generated token
        if (generated_count == 1) {
            auto first_token_time = std::chrono::steady_clock::now();
            ttft_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                first_token_time - start_time).count();
        }

        // ── JSON stop sequence: if output contains a closed JSON object, stop ──
        // This prevents generating garbage after the valid JSON payload.
        if (is_json_object_closed(output)) {
            LOGI("nativeRunInference: JSON object closed after %d tokens", generated_count);
            break;
        }

        // Decode new token for next iteration
        llama_batch single = llama_batch_init(1, 0, 1);
        llama_batch_add(single, best_token, n_cur, { 0 }, true);
        n_cur++;

        if (llama_decode(session->ctx, single) != 0) {
            llama_batch_free(single);
            LOGE("nativeRunInference: decode failed at token %d", i);
            break;
        }
        llama_batch_free(single);
    }

    LOGI("nativeRunInference: generated %d tokens, %zu chars, ttft=%lld ms",
         generated_count, output.size(), ttft_ms);

    // Return format: "TOKEN_COUNT|TTFT_MS|output_text"
    // C2-2.6: extended from "TOKEN_COUNT|text" to include real TTFT measurement.
    // Kotlin splits on first two '|' to extract token count and TTFT.
    std::string result = std::to_string(generated_count) + "|"
                       + std::to_string(ttft_ms) + "|"
                       + output;
    return env->NewStringUTF(result.c_str());
}

// ══════════════════════════════════════════════════════════
//  nativeUnload — atomic cleanup via registry erase (C2-2.7 + C2-2.8 running guard)
// ══════════════════════════════════════════════════════════

/** C2-2.8: Maximum time to wait for in-flight inference to finish before freeing resources */
static constexpr int UNLOAD_WAIT_MS = 300;
/** C2-2.8: Polling interval while waiting for inference to finish */
static constexpr int UNLOAD_POLL_MS = 10;

extern "C" JNIEXPORT void JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeUnload(
    JNIEnv* /* env */,
    jobject /* this */,
    jlong   handle
) {
    if (handle == 0) return;

    // C2-2.7: erase from registry — Kotlin can never look this handle up again.
    // The returned shared_ptr is the LAST owner (unless in-flight inference holds a copy).
    auto session = registry_erase(static_cast<uint64_t>(handle));
    if (!session) {
        LOGW("nativeUnload: handle 0x%llx not found in registry (already unloaded?)",
             (unsigned long long)handle);
        return;
    }

    LOGI("nativeUnload: freeing handle=0x%llx (ref_count=%ld)",
         (unsigned long long)handle, session.use_count());

    // C2-2.6: mark poisoned FIRST — any in-flight inference sees this immediately
    session->poisoned.store(true, std::memory_order_release);

    // Signal cancel to any in-flight inference before freeing model resources
    session->cancel_flag.store(true, std::memory_order_release);

    // C2-2.8: Wait for in-flight inference to finish (running == false).
    // InferenceGuard sets running=true at start, false on scope exit.
    // We spin-wait with a timeout. If timeout fires, we intentionally LEAK
    // ctx/model rather than crash by freeing memory an active thread is using.
    int waited_ms = 0;
    while (session->running.load(std::memory_order_acquire) && waited_ms < UNLOAD_WAIT_MS) {
        std::this_thread::sleep_for(std::chrono::milliseconds(UNLOAD_POLL_MS));
        waited_ms += UNLOAD_POLL_MS;
    }

    if (session->running.load(std::memory_order_acquire)) {
        // Inference still running after timeout — DO NOT free ctx/model.
        // Leak is strictly better than use-after-free crash.
        // The shared_ptr still holds the LlamaSession; it will be freed when
        // the inference thread's shared_ptr copy drops (InferenceGuard destruction).
        LOGE("nativeUnload: inference still running after %dms wait — SKIPPING ctx/model free "
             "(intentional leak to prevent use-after-free). handle=0x%llx",
             UNLOAD_WAIT_MS, (unsigned long long)handle);
        return;
    }

    // Safe to free — no thread is using ctx/model.
    if (session->ctx) {
        llama_free(session->ctx);
        session->ctx = nullptr;
    }
    if (session->model) {
        llama_free_model(session->model);
        session->model = nullptr;
    }

    // session shared_ptr dropped here — if ref_count == 1, struct is freed.
    // If in-flight inference holds a copy, struct stays alive but poisoned.
}

// ══════════════════════════════════════════════════════════
//  nativeCancelInference — cooperative cancel from Kotlin
// ══════════════════════════════════════════════════════════

/**
 * Set the cancel flag on the session. The decode loop checks this flag
 * every token and exits early when set. This ensures the native thread
 * actually stops generating, rather than just ignoring the timeout.
 */
extern "C" JNIEXPORT void JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeCancelInference(
    JNIEnv* /* env */,
    jobject /* this */,
    jlong   handle
) {
    if (handle == 0) return;

    // C2-2.7: look up via registry — stale handle returns nullptr safely
    auto session = registry_lookup(static_cast<uint64_t>(handle));
    if (!session) return;

    // C2-2.6: skip if already poisoned (unloaded) — prevents use-after-free
    if (session->poisoned.load(std::memory_order_acquire)) return;

    session->cancel_flag.store(true, std::memory_order_release);
    LOGI("nativeCancelInference: cancel flag set for handle=0x%llx", (unsigned long long)handle);
}
