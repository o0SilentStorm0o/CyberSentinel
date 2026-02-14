package com.cybersentinel.app.domain.llm

/**
 * LlmRuntime — abstraction over the actual inference backend.
 *
 * Implementations:
 *  - FakeLlmRuntime (C2-1): deterministic fixture responses for E2E testing
 *  - LlamaCppRuntime (C2-2, future): llama.cpp JNI binding for on-device inference
 *
 * Contract:
 *  - runInference() must respect config.timeoutMs (hard kill if exceeded)
 *  - Must return InferenceResult.failure() on any error (never throw)
 *  - Must be thread-safe (inference is called from background thread)
 *  - Must not log raw prompts in release builds
 */
interface LlmRuntime {

    /**
     * Run inference on the given prompt with the given configuration.
     *
     * @param prompt The complete prompt string (from PromptBuilder)
     * @param config Inference configuration (tokens, temperature, timeout)
     * @return InferenceResult — success with raw output or failure with error message
     */
    fun runInference(prompt: String, config: InferenceConfig): InferenceResult

    /**
     * Whether this runtime is currently available for inference.
     *
     * False if: model not loaded, runtime not initialized, kill switch active, etc.
     */
    val isAvailable: Boolean

    /**
     * Human-readable runtime identifier for diagnostics.
     * e.g., "FakeLlmRuntime-v1", "LlamaCpp-Q4_K_M"
     */
    val runtimeId: String

    /**
     * Shut down the runtime, releasing all resources (model memory, JNI handles).
     * Safe to call multiple times.
     */
    fun shutdown()
}
