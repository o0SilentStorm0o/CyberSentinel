package com.cybersentinel.app.domain.llm

/**
 * LlmBenchmarkMetrics — aggregated metrics from LLM self-test / benchmark runs.
 *
 * Collected by LlmSelfTestRunner across N fixture incidents.
 * Used by debug UI "LLM Self-Test" screen and quality dashboards.
 *
 * Design: Pure data classes — no logic, no Android dependencies.
 *
 * Metric categories:
 *  1. Latency — timing across all runs
 *  2. Stability — OOM, timeout, error counts
 *  3. Quality — schema compliance, evidence faithfulness, policy violations
 *  4. Pipeline — parse/validate/fallback rates
 */

// ══════════════════════════════════════════════════════════
//  Aggregated benchmark result
// ══════════════════════════════════════════════════════════

/**
 * Complete benchmark result from one self-test session.
 */
data class LlmBenchmarkResult(
    /** Model identifier */
    val modelId: String,
    /** Model version */
    val modelVersion: String,
    /** Runtime identifier (e.g., "FakeLlmRuntime-v1", "llama_cpp_v1_arm64") */
    val runtimeId: String,
    /** Number of test runs executed */
    val totalRuns: Int,
    /** Latency statistics */
    val latency: LatencyMetrics,
    /** Stability counters */
    val stability: StabilityMetrics,
    /** Quality metrics */
    val quality: QualityMetrics,
    /** Pipeline stage pass rates */
    val pipeline: PipelineMetrics,
    /** Inference configuration used */
    val inferenceConfig: InferenceConfig,
    /** Timestamp when benchmark started */
    val startedAt: Long,
    /** Timestamp when benchmark completed */
    val completedAt: Long,
    /**
     * Peak native heap allocation observed during the benchmark (bytes).
     * Measured via Debug.getNativeHeapAllocatedSize() before/after each run.
     * 0 if not available (e.g., in unit tests where Debug API is stubbed).
     *
     * This is a proxy for memory pressure — "0 OOM in 20 runs" doesn't mean safe
     * if native heap is near the limit. Track this to detect fragmentation/GC pressure
     * before it becomes a production OOM.
     */
    val peakNativeHeapBytes: Long = 0,
    /**
     * C2-2.6: Average number of tokens generated per successful inference run.
     * Helps detect over-generation when stop condition misses.
     */
    val avgGeneratedTokens: Float = 0f,
    /**
     * C2-2.6: Maximum number of tokens generated in any single run.
     * If this equals maxNewTokens, the stop condition likely failed for at least one run —
     * the model hit the token limit instead of producing a closed JSON object.
     */
    val maxGeneratedTokens: Int = 0
) {
    /** Total benchmark duration in milliseconds */
    val durationMs: Long get() = completedAt - startedAt

    /** Overall health score (0.0 - 1.0): weighted combination of key metrics */
    val healthScore: Float
        get() {
            if (totalRuns == 0) return 0f
            val complianceWeight = 0.4f
            val stabilityWeight = 0.3f
            val fallbackWeight = 0.3f
            return (quality.schemaComplianceRate * complianceWeight +
                    stability.successRate * stabilityWeight +
                    (1f - pipeline.templateFallbackRate) * fallbackWeight)
                .coerceIn(0f, 1f)
        }

    /** Human-readable summary for debug UI */
    val summary: String
        get() = buildString {
            appendLine("Model: $modelId ($modelVersion)")
            appendLine("Runtime: $runtimeId")
            appendLine("Runs: $totalRuns | Health: ${"%.0f".format(healthScore * 100)}%")
            appendLine("Latency: avg ${latency.avgMs}ms, p95 ${latency.p95Ms}ms, p99 ${latency.p99Ms}ms")
            appendLine("Compliance: ${"%.1f".format(quality.schemaComplianceRate * 100)}%")
            appendLine("Fallback: ${"%.1f".format(pipeline.templateFallbackRate * 100)}%")
            if (avgGeneratedTokens > 0f) {
                appendLine("Tokens: avg ${"%.1f".format(avgGeneratedTokens)}, max $maxGeneratedTokens")
            }
            if (peakNativeHeapBytes > 0) {
                appendLine("Peak native heap: ${peakNativeHeapBytes / (1024 * 1024)}MB")
            }
            if (stability.oomCount > 0) appendLine("⚠️ OOM: ${stability.oomCount}")
            if (stability.timeoutCount > 0) appendLine("⚠️ Timeouts: ${stability.timeoutCount}")
        }
}

// ══════════════════════════════════════════════════════════
//  Latency metrics
// ══════════════════════════════════════════════════════════

/**
 * Latency statistics across N inference runs.
 */
data class LatencyMetrics(
    /** Average total inference time (ms) */
    val avgMs: Long,
    /** Minimum total inference time (ms) */
    val minMs: Long,
    /** Maximum total inference time (ms) */
    val maxMs: Long,
    /** Median total inference time (ms) */
    val medianMs: Long,
    /** 95th percentile total inference time (ms) */
    val p95Ms: Long,
    /** 99th percentile total inference time (ms) — shows "bad device tails" */
    val p99Ms: Long,
    /** Average time to first token (ms) — estimated if not streaming */
    val avgTtftMs: Long,
    /** Average tokens per second */
    val avgTokensPerSecond: Float
) {
    companion object {
        val EMPTY = LatencyMetrics(0, 0, 0, 0, 0, 0, 0, 0f)

        /**
         * Compute latency metrics from a list of inference results.
         */
        fun fromResults(results: List<InferenceResult>): LatencyMetrics {
            val successful = results.filter { it.success && it.totalTimeMs != null }
            if (successful.isEmpty()) return EMPTY

            val times = successful.mapNotNull { it.totalTimeMs }.sorted()
            val ttfts = successful.mapNotNull { it.timeToFirstTokenMs }
            val tps = successful.mapNotNull { it.tokensPerSecond }

            return LatencyMetrics(
                avgMs = times.average().toLong(),
                minMs = times.first(),
                maxMs = times.last(),
                medianMs = times[times.size / 2],
                p95Ms = times[(times.size * 0.95).toInt().coerceAtMost(times.size - 1)],
                p99Ms = times[(times.size * 0.99).toInt().coerceAtMost(times.size - 1)],
                avgTtftMs = if (ttfts.isNotEmpty()) ttfts.average().toLong() else 0,
                avgTokensPerSecond = if (tps.isNotEmpty()) tps.average().toFloat() else 0f
            )
        }
    }
}

// ══════════════════════════════════════════════════════════
//  Stability metrics
// ══════════════════════════════════════════════════════════

/**
 * Stability counters — how often did inference fail.
 */
data class StabilityMetrics(
    /** Total number of inference calls */
    val totalCalls: Int,
    /** Number of successful inference completions */
    val successCount: Int,
    /** Number of OOM failures (native or JVM) */
    val oomCount: Int,
    /** Number of timeout failures */
    val timeoutCount: Int,
    /** Number of other errors */
    val otherErrorCount: Int
) {
    /** Success rate (0.0 - 1.0) */
    val successRate: Float
        get() = if (totalCalls > 0) successCount.toFloat() / totalCalls else 0f

    /** Failure rate (0.0 - 1.0) */
    val failureRate: Float get() = 1f - successRate

    companion object {
        val EMPTY = StabilityMetrics(0, 0, 0, 0, 0)

        fun fromResults(results: List<InferenceResult>): StabilityMetrics {
            var oom = 0; var timeout = 0; var other = 0; var success = 0
            for (r in results) {
                if (r.success) { success++; continue }
                val err = r.error?.lowercase() ?: ""
                when {
                    err.contains("oom") || err.contains("out of memory") -> oom++
                    err.contains("timeout") -> timeout++
                    else -> other++
                }
            }
            return StabilityMetrics(results.size, success, oom, timeout, other)
        }
    }
}

// ══════════════════════════════════════════════════════════
//  Quality metrics
// ══════════════════════════════════════════════════════════

/**
 * Quality metrics — how good is the LLM output for our use-case.
 */
data class QualityMetrics(
    /** Rate of outputs that pass STRICT parse + validate without any repairs (0.0-1.0) */
    val schemaComplianceRate: Float,
    /** Rate of outputs where all reason_ids are valid subset of incident evidence (0.0-1.0) */
    val evidenceFaithfulnessRate: Float,
    /** Number of outputs that violated PolicyGuard constraints */
    val policyViolationCount: Int,
    /** Average confidence across successful parses */
    val avgConfidence: Double,
    /** Total outputs that required SlotValidator repair (not rejected, just repaired) */
    val repairedCount: Int,
    /** Total outputs rejected by SlotValidator STRICT mode */
    val rejectedCount: Int
) {
    companion object {
        val EMPTY = QualityMetrics(0f, 0f, 0, 0.0, 0, 0)
    }
}

// ══════════════════════════════════════════════════════════
//  Pipeline metrics
// ══════════════════════════════════════════════════════════

/**
 * Pipeline stage pass rates.
 */
data class PipelineMetrics(
    /** Rate of inference calls that returned success (0.0-1.0) */
    val inferenceSuccessRate: Float,
    /** Rate of outputs that parsed successfully (0.0-1.0) */
    val parseSuccessRate: Float,
    /** Rate of parsed outputs that validated (Valid or Repaired) (0.0-1.0) */
    val validatePassRate: Float,
    /** Rate of outputs that needed SlotValidator repair (0.0-1.0) */
    val validateRepairRate: Float,
    /** Rate of total calls that fell back to template engine (0.0-1.0) */
    val templateFallbackRate: Float
) {
    companion object {
        val EMPTY = PipelineMetrics(0f, 0f, 0f, 0f, 0f)
    }
}

// ══════════════════════════════════════════════════════════
//  Single run result (for per-run analysis)
// ══════════════════════════════════════════════════════════

/**
 * Result of a single self-test run — tracks each pipeline stage.
 */
data class SingleRunResult(
    val runIndex: Int,
    val severity: com.cybersentinel.app.domain.security.IncidentSeverity,
    val inferenceResult: InferenceResult,
    val parseResult: ParseResult?,
    val validationResult: ValidationResult?,
    val engineSource: com.cybersentinel.app.domain.explainability.EngineSource,
    val totalPipelineMs: Long
) {
    val wasLlmAssisted: Boolean
        get() = engineSource == com.cybersentinel.app.domain.explainability.EngineSource.LLM_ASSISTED
    val wasFallback: Boolean
        get() = engineSource == com.cybersentinel.app.domain.explainability.EngineSource.LLM_FALLBACK_TO_TEMPLATE
}
