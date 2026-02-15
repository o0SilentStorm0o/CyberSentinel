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
 * Design decisions (C2-2.5 hardening):
 *   - Static link ggml + llama.cpp (no separate .so for ggml)
 *   - CPU-only inference (no Vulkan/NNAPI in C2-2; future C2-4)
 *   - Hard n_ctx ceiling (2048 default — slots-only prompts are short)
 *   - DETERMINISTIC sampling: temperature=0, greedy top-1 (no randomness)
 *   - Cooperative cancel flag: checked every token in decode loop
 *   - JSON stop sequence: stops on closed JSON object (balanced braces)
 *   - Hard timeout via elapsed-time check each token
 *   - No streaming — returns "token_count|output_text" on completion
 *   - Single model context per handle (no batched inference)
 *   - LlamaSession struct owns model+context+cancel atomically
 *
 * Return format: "TOKEN_COUNT|generated_text"
 *   Kotlin side splits on first '|' to get exact token count.
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
 * Single-owner session struct. The jlong handle IS a pointer to this struct.
 * Ensures model and context are freed together, and cancel flag is per-session.
 */
struct LlamaSession {
    llama_model*       model       = nullptr;
    llama_context*     ctx         = nullptr;
    int                n_ctx       = 2048;
    int                n_threads   = 4;
    std::atomic<bool>  cancel_flag{false};  // cooperative cancel — checked every token
};

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

    auto* session = new LlamaSession();
    session->model     = model;
    session->ctx       = ctx;
    session->n_ctx     = contextSize;
    session->n_threads = nThreads;
    session->cancel_flag.store(false);

    LOGI("nativeLoadModel: model loaded successfully (session=%p)", session);
    return reinterpret_cast<jlong>(session);
}

// ══════════════════════════════════════════════════════════
//  nativeRunInference — deterministic greedy + cooperative cancel
// ══════════════════════════════════════════════════════════

/**
 * Helper: check if generated JSON object is closed (balanced braces).
 * Returns true when we've seen at least one '{' and brace depth returns to 0.
 */
static bool is_json_object_closed(const std::string& text) {
    int depth = 0;
    bool seen_open = false;
    for (char c : text) {
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
        return env->NewStringUTF("ERROR: null handle");
    }

    auto* session = reinterpret_cast<LlamaSession*>(handle);
    if (!session->model || !session->ctx) {
        return env->NewStringUTF("ERROR: model or context is null");
    }

    // Reset cancel flag at inference start
    session->cancel_flag.store(false);

    const char* promptCStr = env->GetStringUTFChars(jPrompt, nullptr);
    if (!promptCStr) {
        return env->NewStringUTF("ERROR: null prompt");
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
        return env->NewStringUTF("ERROR: tokenization failed");
    }
    tokens.resize(n_tokens);

    // Check if prompt fits in context
    if (n_tokens >= session->n_ctx) {
        LOGW("nativeRunInference: prompt too long (%d tokens > n_ctx=%d)", n_tokens, session->n_ctx);
        return env->NewStringUTF("ERROR: prompt exceeds context window");
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
        return env->NewStringUTF("ERROR: prompt decode failed");
    }
    llama_batch_free(batch);

    // ── Deterministic greedy decode loop ──
    // temperature=0 → always pick highest-logit token (argmax / greedy)
    // No top-p, no sampling from distribution → maximal schema compliance
    auto start_time = std::chrono::steady_clock::now();
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

    LOGI("nativeRunInference: generated %d tokens, %zu chars", generated_count, output.size());

    // Return format: "TOKEN_COUNT|output_text"
    // Kotlin splits on first '|' to extract exact generated token count.
    std::string result = std::to_string(generated_count) + "|" + output;
    return env->NewStringUTF(result.c_str());
}

// ══════════════════════════════════════════════════════════
//  nativeUnload — atomic cleanup of session struct
// ══════════════════════════════════════════════════════════

extern "C" JNIEXPORT void JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeUnload(
    JNIEnv* /* env */,
    jobject /* this */,
    jlong   handle
) {
    if (handle == 0) return;

    auto* session = reinterpret_cast<LlamaSession*>(handle);
    LOGI("nativeUnload: freeing session=%p", session);

    // Signal cancel to any in-flight inference before freeing
    session->cancel_flag.store(true, std::memory_order_release);

    if (session->ctx) {
        llama_free(session->ctx);
        session->ctx = nullptr;
    }
    if (session->model) {
        llama_free_model(session->model);
        session->model = nullptr;
    }

    delete session;
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
    auto* session = reinterpret_cast<LlamaSession*>(handle);
    session->cancel_flag.store(true, std::memory_order_release);
    LOGI("nativeCancelInference: cancel flag set for session=%p", session);
}
