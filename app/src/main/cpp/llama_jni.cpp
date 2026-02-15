/**
 * llama_jni.cpp — JNI bridge between LlamaCppRuntime.kt and llama.cpp C API.
 *
 * This file provides the minimal JNI surface for CyberSentinel's slots-only
 * inference pipeline:
 *   1. nativeLoadModel   — load GGUF model into memory
 *   2. nativeRunInference — run completion (prompt → slots JSON)
 *   3. nativeUnload       — free model + context
 *
 * Design decisions:
 *   - Static link ggml + llama.cpp (no separate .so for ggml)
 *   - CPU-only inference (no Vulkan/NNAPI in C2-2; future C2-4)
 *   - Hard n_ctx ceiling (2048 default — slots-only prompts are short)
 *   - Hard timeout via token callback (checks elapsed time each token)
 *   - No streaming — returns full output string on completion
 *   - Single model context per handle (no batched inference)
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
#include <android/log.h>

// llama.cpp headers (paths resolved by CMake include_directories)
#include "llama.h"
#include "common.h"

#define TAG "LlamaJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ══════════════════════════════════════════════════════════
//  Native context — holds llama model + context per handle
// ══════════════════════════════════════════════════════════

struct LlamaContext {
    llama_model*   model   = nullptr;
    llama_context* ctx     = nullptr;
    int            n_ctx   = 2048;
    int            n_threads = 4;
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

    auto* wrapper = new LlamaContext();
    wrapper->model     = model;
    wrapper->ctx       = ctx;
    wrapper->n_ctx     = contextSize;
    wrapper->n_threads = nThreads;

    LOGI("nativeLoadModel: model loaded successfully (handle=%p)", wrapper);
    return reinterpret_cast<jlong>(wrapper);
}

// ══════════════════════════════════════════════════════════
//  nativeRunInference
// ══════════════════════════════════════════════════════════

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

    auto* wrapper = reinterpret_cast<LlamaContext*>(handle);
    if (!wrapper->model || !wrapper->ctx) {
        return env->NewStringUTF("ERROR: model or context is null");
    }

    const char* promptCStr = env->GetStringUTFChars(jPrompt, nullptr);
    if (!promptCStr) {
        return env->NewStringUTF("ERROR: null prompt");
    }
    std::string prompt(promptCStr);
    env->ReleaseStringUTFChars(jPrompt, promptCStr);

    // Tokenize prompt
    const int n_prompt_max = wrapper->n_ctx;
    std::vector<llama_token> tokens(n_prompt_max);
    int n_tokens = llama_tokenize(
        wrapper->model,
        prompt.c_str(),
        static_cast<int32_t>(prompt.size()),
        tokens.data(),
        n_prompt_max,
        true,   // add_bos
        false   // special
    );

    if (n_tokens < 0) {
        LOGE("nativeRunInference: tokenization failed (n_tokens=%d)", n_tokens);
        return env->NewStringUTF("ERROR: tokenization failed");
    }
    tokens.resize(n_tokens);

    // Check if prompt fits in context
    if (n_tokens >= wrapper->n_ctx) {
        LOGW("nativeRunInference: prompt too long (%d tokens > n_ctx=%d)", n_tokens, wrapper->n_ctx);
        return env->NewStringUTF("ERROR: prompt exceeds context window");
    }

    // Clear KV cache for fresh inference
    llama_kv_cache_clear(wrapper->ctx);

    // Decode prompt (prefill)
    llama_batch batch = llama_batch_init(n_tokens, 0, 1);
    for (int i = 0; i < n_tokens; i++) {
        llama_batch_add(batch, tokens[i], i, { 0 }, false);
    }
    // Last token needs logits
    batch.logits[batch.n_tokens - 1] = true;

    if (llama_decode(wrapper->ctx, batch) != 0) {
        llama_batch_free(batch);
        LOGE("nativeRunInference: prompt decode failed");
        return env->NewStringUTF("ERROR: prompt decode failed");
    }
    llama_batch_free(batch);

    // Sampling + generation
    auto start_time = std::chrono::steady_clock::now();
    std::string output;
    output.reserve(maxTokens * 8); // rough estimate

    const llama_token eos = llama_token_eos(wrapper->model);
    int n_cur = n_tokens;

    for (int i = 0; i < maxTokens; i++) {
        // Timeout check
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed_ms > timeoutMs) {
            LOGW("nativeRunInference: timeout after %lld ms", (long long)elapsed_ms);
            break; // Return partial output rather than error
        }

        // Sample next token
        auto* logits = llama_get_logits_ith(wrapper->ctx, -1);
        int n_vocab = llama_n_vocab(wrapper->model);

        // Temperature + top-p sampling
        std::vector<llama_token_data> candidates(n_vocab);
        for (int t = 0; t < n_vocab; t++) {
            candidates[t] = llama_token_data{ t, logits[t], 0.0f };
        }

        llama_token_data_array candidates_p = {
            candidates.data(),
            static_cast<size_t>(n_vocab),
            false
        };

        // Apply temperature
        llama_sample_temp(wrapper->ctx, &candidates_p, temperature);
        // Apply top-p
        llama_sample_top_p(wrapper->ctx, &candidates_p, topP, 1);
        // Pick token
        llama_token new_token = llama_sample_token(wrapper->ctx, &candidates_p);

        // Check EOS
        if (new_token == eos) {
            break;
        }

        // Convert token to text
        char buf[256];
        int n_chars = llama_token_to_piece(wrapper->model, new_token, buf, sizeof(buf), 0, true);
        if (n_chars > 0) {
            output.append(buf, n_chars);
        }

        // Stop sequences check: ``` or triple newline
        if (output.find("```") != std::string::npos ||
            output.find("\n\n\n") != std::string::npos) {
            // Trim the stop sequence
            auto pos = output.find("```");
            if (pos != std::string::npos) output = output.substr(0, pos);
            pos = output.find("\n\n\n");
            if (pos != std::string::npos) output = output.substr(0, pos);
            break;
        }

        // Decode new token for next iteration
        llama_batch single = llama_batch_init(1, 0, 1);
        llama_batch_add(single, new_token, n_cur, { 0 }, true);
        n_cur++;

        if (llama_decode(wrapper->ctx, single) != 0) {
            llama_batch_free(single);
            LOGE("nativeRunInference: decode failed at token %d", i);
            break;
        }
        llama_batch_free(single);
    }

    LOGI("nativeRunInference: generated %zu chars", output.size());
    return env->NewStringUTF(output.c_str());
}

// ══════════════════════════════════════════════════════════
//  nativeUnload
// ══════════════════════════════════════════════════════════

extern "C" JNIEXPORT void JNICALL
Java_com_cybersentinel_app_domain_llm_LlamaCppRuntime_nativeUnload(
    JNIEnv* /* env */,
    jobject /* this */,
    jlong   handle
) {
    if (handle == 0) return;

    auto* wrapper = reinterpret_cast<LlamaContext*>(handle);
    LOGI("nativeUnload: freeing handle=%p", wrapper);

    if (wrapper->ctx) {
        llama_free(wrapper->ctx);
        wrapper->ctx = nullptr;
    }
    if (wrapper->model) {
        llama_free_model(wrapper->model);
        wrapper->model = nullptr;
    }

    delete wrapper;
}
