package com.cybersentinel.app.domain.llm

/**
 * LLM Infrastructure Models — data classes for the local inference pipeline.
 *
 * Covers:
 *  1. Model metadata and lifecycle (ModelManifest, ModelInfo, ModelState)
 *  2. Inference configuration and results
 *  3. Download/integrity tracking
 *
 * Design: Pure data classes. No logic. No Android dependencies.
 * These live in the domain layer and are used by both the inference engine
 * and the model manager.
 */

// ══════════════════════════════════════════════════════════
//  Model metadata
// ══════════════════════════════════════════════════════════

/**
 * Remote model manifest — describes available models from the server.
 *
 * Fetched from GitHub releases / remote config / CDN.
 * Contains all information needed to decide whether to download.
 */
data class ModelManifest(
    /** Unique model identifier (e.g., "cybersentinel-slots-q4-v1") */
    val modelId: String,
    /** Human-readable model name */
    val displayName: String,
    /** Model version string (semver) */
    val version: String,
    /** Download URL for the GGUF model file */
    val downloadUrl: String,
    /** Expected file size in bytes */
    val fileSizeBytes: Long,
    /** SHA-256 hash of the model file for integrity verification */
    val sha256: String,
    /** Quantization type (e.g., "Q4_K_M", "Q4_0") */
    val quantization: String,
    /** Minimum app version required to use this model */
    val minAppVersion: Int = 1,
    /** Minimum RAM in MB required */
    val minRamMb: Long = 4000,
    /** Whether this model requires 64-bit ABI */
    val requires64Bit: Boolean = true,
    /** Max recommended tokens for generation */
    val recommendedMaxTokens: Int = 160,
    /** Default temperature for inference */
    val recommendedTemperature: Float = 0.1f
)

/**
 * Local model info — describes a model that is downloaded and ready.
 */
data class ModelInfo(
    /** Model ID from manifest */
    val modelId: String,
    /** Version from manifest */
    val version: String,
    /** Absolute path to the GGUF file on device */
    val localPath: String,
    /** File size in bytes (verified) */
    val fileSizeBytes: Long,
    /** SHA-256 verified at download time */
    val sha256: String,
    /** Timestamp when this model was downloaded */
    val downloadedAt: Long,
    /** Timestamp when this model was last used for inference */
    val lastUsedAt: Long? = null,
    /** Number of successful inferences with this model */
    val inferenceCount: Int = 0
)

/**
 * Model lifecycle state.
 */
enum class ModelState {
    /** No model downloaded — template engine only */
    NOT_DOWNLOADED,
    /** Model is currently downloading */
    DOWNLOADING,
    /** Download complete, integrity verified, ready to load */
    READY,
    /** Model is loaded into memory (inference possible) */
    LOADED,
    /** Model failed integrity check or is corrupted */
    CORRUPTED,
    /** Model version is disabled by kill switch */
    KILLED
}

/**
 * Download progress tracking.
 */
data class DownloadProgress(
    val modelId: String,
    val totalBytes: Long,
    val downloadedBytes: Long,
    val state: DownloadState
) {
    val progressPercent: Int
        get() = if (totalBytes > 0) ((downloadedBytes * 100) / totalBytes).toInt() else 0
}

enum class DownloadState {
    IDLE,
    DOWNLOADING,
    VERIFYING,
    COMPLETED,
    FAILED
}

// ══════════════════════════════════════════════════════════
//  Inference configuration and results
// ══════════════════════════════════════════════════════════

/**
 * Configuration for a single inference call.
 *
 * Keeps inference tightly constrained — we generate structured slots, not essays.
 *
 * C2-2.5 note: temperature is set to 0.0 (deterministic greedy) for maximum
 * schema compliance. The JNI layer enforces greedy argmax regardless of this
 * value, but we set it here for documentation and future runtime switchability.
 * topP is set to 1.0 (no nucleus filtering — greedy picks the single best token).
 */
data class InferenceConfig(
    /** Maximum new tokens to generate (keep low for slot-only output) */
    val maxNewTokens: Int = 160,
    /** Temperature: 0.0 = deterministic greedy (C2-2.5: always 0 for slots-only) */
    val temperature: Float = 0.0f,
    /** Top-p: 1.0 = no filtering (C2-2.5: greedy argmax, topP ignored by JNI) */
    val topP: Float = 1.0f,
    /** Stop sequences — stop generation when any of these are produced */
    val stopSequences: List<String> = listOf("```", "\n\n\n"),
    /** Timeout in milliseconds — hard limit on inference time */
    val timeoutMs: Long = 15_000,
    /** Whether to include timing info in the result */
    val measureTiming: Boolean = true
) {
    companion object {
        /** Default config optimized for deterministic structured slot generation */
        val SLOTS_DEFAULT = InferenceConfig(
            maxNewTokens = 160,
            temperature = 0.0f,
            topP = 1.0f,
            timeoutMs = 15_000
        )

        /** More conservative config for Tier 1 devices (lower token budget, longer timeout) */
        val TIER1_CONSERVATIVE = InferenceConfig(
            maxNewTokens = 120,
            temperature = 0.0f,
            topP = 1.0f,
            timeoutMs = 20_000
        )
    }
}

/**
 * Result of a single inference call.
 *
 * Contains raw output + timing metrics for quality tracking.
 */
data class InferenceResult(
    /** Raw text output from the model */
    val rawOutput: String,
    /** Whether inference completed successfully */
    val success: Boolean,
    /** Error message if failed */
    val error: String? = null,
    /** Time to first token in milliseconds */
    val timeToFirstTokenMs: Long? = null,
    /** Total inference time in milliseconds */
    val totalTimeMs: Long? = null,
    /**
     * Number of tokens generated.
     *
     * Three-state semantics (C2-2.7):
     * - `null`  — inference never ran or failed before generating any output.
     * - `0`     — inference ran but produced no usable tokens (e.g. parse fallback).
     * - `> 0`   — actual token count reported by the runtime.
     *
     * Callers (e.g. [LlmSelfTestRunner]) MUST use `?.let` / null-check
     * to exclude failures from token-count aggregations.
     */
    val tokensGenerated: Int? = null,
    /** Tokens per second (throughput) */
    val tokensPerSecond: Float? = null
) {
    companion object {
        fun success(
            rawOutput: String,
            timeToFirstTokenMs: Long? = null,
            totalTimeMs: Long? = null,
            tokensGenerated: Int? = null
        ) = InferenceResult(
            rawOutput = rawOutput,
            success = true,
            timeToFirstTokenMs = timeToFirstTokenMs,
            totalTimeMs = totalTimeMs,
            tokensGenerated = tokensGenerated,
            tokensPerSecond = if (tokensGenerated != null && totalTimeMs != null && totalTimeMs > 0)
                (tokensGenerated * 1000f) / totalTimeMs else null
        )

        fun failure(error: String, totalTimeMs: Long? = null) = InferenceResult(
            rawOutput = "",
            success = false,
            error = error,
            totalTimeMs = totalTimeMs
        )
    }
}

// ══════════════════════════════════════════════════════════
//  Diagnostics (for debug self-test screen)
// ══════════════════════════════════════════════════════════

/**
 * LLM self-test result — for the debug menu "LLM self-test" screen.
 */
data class LlmSelfTestResult(
    val modelId: String,
    val modelVersion: String,
    /** Average inference latency over N runs (ms) */
    val avgLatencyMs: Long,
    /** Schema compliance rate: how often LLM output parses correctly (0.0-1.0) */
    val schemaComplianceRate: Float,
    /** Did any test run trigger OOM? */
    val oomDetected: Boolean,
    /** Number of test runs */
    val testRunCount: Int,
    /** Number of successful parses */
    val successfulParses: Int,
    /** Average tokens per second */
    val avgTokensPerSecond: Float,
    /** Timestamp of the test */
    val timestamp: Long = System.currentTimeMillis()
) {
    val passRate: Float
        get() = if (testRunCount > 0) successfulParses.toFloat() / testRunCount else 0f
}
