package com.cybersentinel.app.domain.llm

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for LlmBenchmarkMetrics data classes — C2-2.5.
 *
 * Verifies: computed properties, edge cases, companion object factories.
 * C2-2.5: LatencyMetrics now includes p99Ms, LlmBenchmarkResult includes peakNativeHeapBytes.
 */
class LlmBenchmarkMetricsTest {

    // ══════════════════════════════════════════════════════════
    //  LatencyMetrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LatencyMetrics EMPTY has all zeros`() {
        val m = LatencyMetrics.EMPTY
        assertEquals(0L, m.avgMs)
        assertEquals(0L, m.minMs)
        assertEquals(0L, m.maxMs)
        assertEquals(0L, m.medianMs)
        assertEquals(0L, m.p95Ms)
        assertEquals(0L, m.p99Ms)
        assertEquals(0L, m.avgTtftMs)
        assertEquals(0f, m.avgTokensPerSecond, 0.001f)
    }

    @Test
    fun `LatencyMetrics fromResults with single result`() {
        val results = listOf(
            InferenceResult.success("out", timeToFirstTokenMs = 10, totalTimeMs = 50, tokensGenerated = 25)
        )
        val m = LatencyMetrics.fromResults(results)
        assertEquals(50L, m.avgMs)
        assertEquals(50L, m.minMs)
        assertEquals(50L, m.maxMs)
        assertEquals(50L, m.medianMs)
        assertEquals(50L, m.p95Ms)
        assertEquals(50L, m.p99Ms)
        assertEquals(10L, m.avgTtftMs)
        assertTrue(m.avgTokensPerSecond > 0f)
    }

    @Test
    fun `LatencyMetrics fromResults ignores failed results`() {
        val results = listOf(
            InferenceResult.success("ok", totalTimeMs = 100, tokensGenerated = 10),
            InferenceResult.failure("error", totalTimeMs = 500)
        )
        val m = LatencyMetrics.fromResults(results)
        assertEquals(100L, m.avgMs) // only the successful one
    }

    @Test
    fun `LatencyMetrics fromResults with all failures returns EMPTY`() {
        val results = listOf(
            InferenceResult.failure("err1"),
            InferenceResult.failure("err2")
        )
        val m = LatencyMetrics.fromResults(results)
        assertEquals(LatencyMetrics.EMPTY, m)
    }

    // ══════════════════════════════════════════════════════════
    //  StabilityMetrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `StabilityMetrics EMPTY has all zeros`() {
        val m = StabilityMetrics.EMPTY
        assertEquals(0, m.totalCalls)
        assertEquals(0, m.successCount)
        assertEquals(0f, m.successRate, 0.001f)
        assertEquals(1f, m.failureRate, 0.001f) // 1 - 0 = 1... but totalCalls=0 → 0/0=0 → 1-0=1
    }

    @Test
    fun `StabilityMetrics successRate calculation`() {
        val m = StabilityMetrics(totalCalls = 10, successCount = 8, oomCount = 1, timeoutCount = 1, otherErrorCount = 0)
        assertEquals(0.8f, m.successRate, 0.001f)
        assertEquals(0.2f, m.failureRate, 0.001f)
    }

    @Test
    fun `StabilityMetrics fromResults detects OOM keyword`() {
        val results = listOf(
            InferenceResult.failure("Out of memory in native heap")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(1, m.oomCount)
    }

    @Test
    fun `StabilityMetrics fromResults detects timeout keyword`() {
        val results = listOf(
            InferenceResult.failure("Timeout exceeded (15000ms)")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(1, m.timeoutCount)
    }

    // ══════════════════════════════════════════════════════════
    //  QualityMetrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `QualityMetrics EMPTY has all zeros`() {
        val m = QualityMetrics.EMPTY
        assertEquals(0f, m.schemaComplianceRate, 0.001f)
        assertEquals(0f, m.evidenceFaithfulnessRate, 0.001f)
        assertEquals(0, m.policyViolationCount)
        assertEquals(0.0, m.avgConfidence, 0.001)
    }

    // ══════════════════════════════════════════════════════════
    //  PipelineMetrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `PipelineMetrics EMPTY has all zeros`() {
        val m = PipelineMetrics.EMPTY
        assertEquals(0f, m.inferenceSuccessRate, 0.001f)
        assertEquals(0f, m.parseSuccessRate, 0.001f)
        assertEquals(0f, m.validatePassRate, 0.001f)
        assertEquals(0f, m.validateRepairRate, 0.001f)
        assertEquals(0f, m.templateFallbackRate, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  LlmBenchmarkResult
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LlmBenchmarkResult healthScore is in 0-1 range`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 10,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(10, 10, 0, 0, 0),
            quality = QualityMetrics(0.9f, 0.9f, 0, 0.8, 1, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 1000,
            completedAt = 2000
        )
        assertTrue(result.healthScore in 0f..1f)
    }

    @Test
    fun `LlmBenchmarkResult durationMs is correct`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 0,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics.EMPTY,
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 1000,
            completedAt = 5000
        )
        assertEquals(4000L, result.durationMs)
    }

    @Test
    fun `LlmBenchmarkResult healthScore is 0 with zero runs`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 0,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics.EMPTY,
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        assertEquals(0f, result.healthScore, 0.001f)
    }

    @Test
    fun `LlmBenchmarkResult summary is not blank`() {
        val result = LlmBenchmarkResult(
            modelId = "my-model",
            modelVersion = "1.0",
            runtimeId = "test-runtime",
            totalRuns = 5,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(5, 5, 0, 0, 0),
            quality = QualityMetrics(0.8f, 0.9f, 0, 0.75, 1, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.8f, 0.1f, 0.2f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 1000,
            completedAt = 2000
        )
        assertTrue(result.summary.isNotBlank())
        assertTrue(result.summary.contains("my-model"))
    }

    // ══════════════════════════════════════════════════════════
    //  SingleRunResult
    // ══════════════════════════════════════════════════════════

    @Test
    fun `SingleRunResult wasLlmAssisted is correct`() {
        val run = SingleRunResult(
            runIndex = 0,
            severity = com.cybersentinel.app.domain.security.IncidentSeverity.MEDIUM,
            inferenceResult = InferenceResult.success("ok"),
            parseResult = null,
            validationResult = null,
            engineSource = com.cybersentinel.app.domain.explainability.EngineSource.LLM_ASSISTED,
            totalPipelineMs = 50
        )
        assertTrue(run.wasLlmAssisted)
        assertFalse(run.wasFallback)
    }

    @Test
    fun `SingleRunResult wasFallback is correct`() {
        val run = SingleRunResult(
            runIndex = 0,
            severity = com.cybersentinel.app.domain.security.IncidentSeverity.MEDIUM,
            inferenceResult = InferenceResult.failure("error"),
            parseResult = null,
            validationResult = null,
            engineSource = com.cybersentinel.app.domain.explainability.EngineSource.LLM_FALLBACK_TO_TEMPLATE,
            totalPipelineMs = 10
        )
        assertTrue(run.wasFallback)
        assertFalse(run.wasLlmAssisted)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.6: Token generation stats
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LlmBenchmarkResult default token stats are zero`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 0,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics.EMPTY,
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        assertEquals(0f, result.avgGeneratedTokens, 0.001f)
        assertEquals(0, result.maxGeneratedTokens)
    }

    @Test
    fun `LlmBenchmarkResult with token stats shows them in summary`() {
        val result = LlmBenchmarkResult(
            modelId = "token-test",
            modelVersion = "1.0",
            runtimeId = "test-runtime",
            totalRuns = 5,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(5, 5, 0, 0, 0),
            quality = QualityMetrics(0.8f, 0.9f, 0, 0.75, 1, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.8f, 0.1f, 0.2f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 1000,
            completedAt = 2000,
            avgGeneratedTokens = 35.5f,
            maxGeneratedTokens = 50
        )
        assertTrue("Summary should contain 'Tokens'", result.summary.contains("Tokens"))
        assertTrue("Summary should contain max tokens", result.summary.contains("50"))
    }

    @Test
    fun `LlmBenchmarkResult peakNativeHeapBytes default is zero`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 0,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics.EMPTY,
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        assertEquals(0L, result.peakNativeHeapBytes)
    }
}
