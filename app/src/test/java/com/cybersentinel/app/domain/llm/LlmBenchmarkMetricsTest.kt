package com.cybersentinel.app.domain.llm

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for LlmBenchmarkMetrics data classes — C2-2.5 + C2-2.7 + C2-2.8.
 *
 * Verifies: computed properties, edge cases, companion object factories.
 * C2-2.5: LatencyMetrics now includes p99Ms, LlmBenchmarkResult includes peakNativeHeapBytes.
 * C2-2.7: StabilityMetrics.busyCount, stopFailureRate, isProductionReady gate.
 * C2-2.8: busyRate, MIN_STRICT_PASS_RATE, MAX_POLICY_VIOLATION_RATE, stricter gate.
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

    // ══════════════════════════════════════════════════════════
    //  C2-2.7: StabilityMetrics.busyCount
    // ══════════════════════════════════════════════════════════

    @Test
    fun `StabilityMetrics EMPTY has busyCount zero`() {
        assertEquals(0, StabilityMetrics.EMPTY.busyCount)
    }

    @Test
    fun `StabilityMetrics fromResults detects busy keyword`() {
        val results = listOf(
            InferenceResult.failure("Inference busy (single-flight)"),
            InferenceResult.success("ok")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(1, m.busyCount)
        assertEquals(1, m.successCount)
        // busy should NOT be in oom/timeout/other
        assertEquals(0, m.oomCount)
        assertEquals(0, m.timeoutCount)
        assertEquals(0, m.otherErrorCount)
    }

    @Test
    fun `StabilityMetrics busyCount not counted as error`() {
        val results = listOf(
            InferenceResult.failure("busy"),
            InferenceResult.failure("busy"),
            InferenceResult.success("ok")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(2, m.busyCount)
        assertEquals(0, m.realErrorCount)
    }

    @Test
    fun `StabilityMetrics realErrorCount excludes busy`() {
        val results = listOf(
            InferenceResult.failure("OOM"),
            InferenceResult.failure("Timeout"),
            InferenceResult.failure("busy"),
            InferenceResult.failure("unknown error")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(1, m.busyCount)
        assertEquals(3, m.realErrorCount)  // oom + timeout + other
        assertEquals(1, m.oomCount)
        assertEquals(1, m.timeoutCount)
        assertEquals(1, m.otherErrorCount)
    }

    @Test
    fun `StabilityMetrics busy detection is case insensitive`() {
        val results = listOf(
            InferenceResult.failure("BUSY runtime")
        )
        val m = StabilityMetrics.fromResults(results)
        assertEquals(1, m.busyCount)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.7: stopFailureRate + isProductionReady
    // ══════════════════════════════════════════════════════════

    @Test
    fun `stopFailureRate default is zero`() {
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
        assertEquals(0f, result.stopFailureRate, 0.001f)
    }

    @Test
    fun `isProductionReady true for good benchmark`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.9f, 0.9f, 0, 0.8, 0, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 1000,
            completedAt = 2000,
            stopFailureRate = 0.01f  // 1% < 2% threshold
        )
        assertTrue("Should be production ready", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when too few runs`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 5,  // < MIN_PRODUCTION_RUNS (10)
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(5, 5, 0, 0, 0),
            quality = QualityMetrics(0.9f, 0.9f, 0, 0.8, 0, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be production ready with < 10 runs", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when stopFailureRate too high`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.9f, 0.9f, 0, 0.8, 0, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0.05f  // 5% > 2% threshold
        )
        assertFalse("Should NOT be ready with 5% stop-fail", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when healthScore too low`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(20, 5, 5, 5, 5),  // 25% success → low healthScore
            quality = QualityMetrics(0.1f, 0.1f, 10, 0.1, 0, 0),
            pipeline = PipelineMetrics(0.25f, 0.1f, 0.1f, 0f, 0.8f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be ready with low health", result.isProductionReady)
        assertTrue("healthScore should be < MIN_HEALTH_SCORE",
            result.healthScore < LlmBenchmarkResult.MIN_HEALTH_SCORE)
    }

    @Test
    fun `companion constants have expected values`() {
        assertEquals(0.02f, LlmBenchmarkResult.MAX_STOP_FAILURE_RATE, 0.0001f)
        assertEquals(0.70f, LlmBenchmarkResult.MIN_HEALTH_SCORE, 0.0001f)
        assertEquals(10, LlmBenchmarkResult.MIN_PRODUCTION_RUNS)
    }

    @Test
    fun `summary contains production ready YES for good result`() {
        val result = LlmBenchmarkResult(
            modelId = "prod-test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.9f, 0.9f, 0, 0.8, 0, 0),
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertTrue("Summary should contain YES", result.summary.contains("YES"))
    }

    @Test
    fun `summary contains production ready NO for bad result`() {
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
        assertTrue("Summary should contain NO", result.summary.contains("NO"))
    }

    @Test
    fun `summary contains stop-fail when rate positive`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 10,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(10, 10, 0, 0, 0),
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0,
            stopFailureRate = 0.10f
        )
        assertTrue("Summary should mention Stop-fail", result.summary.contains("Stop-fail"))
    }

    @Test
    fun `summary contains busy count when positive`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 10,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(10, 8, 0, 0, 0, busyCount = 2),
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        assertTrue("Summary should mention Busy", result.summary.contains("Busy"))
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.8: busyRate computed property
    // ══════════════════════════════════════════════════════════

    @Test
    fun `busyRate is zero when no calls`() {
        val metrics = StabilityMetrics.EMPTY
        assertEquals(0f, metrics.busyRate, 0.0001f)
    }

    @Test
    fun `busyRate is zero when no busy rejections`() {
        val metrics = StabilityMetrics(20, 20, 0, 0, 0, busyCount = 0)
        assertEquals(0f, metrics.busyRate, 0.0001f)
    }

    @Test
    fun `busyRate correct ratio`() {
        val metrics = StabilityMetrics(100, 90, 2, 1, 2, busyCount = 5)
        assertEquals(0.05f, metrics.busyRate, 0.0001f)
    }

    @Test
    fun `busyRate 100 percent when all calls busy`() {
        val metrics = StabilityMetrics(10, 0, 0, 0, 0, busyCount = 10)
        assertEquals(1.0f, metrics.busyRate, 0.0001f)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.8: companion constants
    // ══════════════════════════════════════════════════════════

    @Test
    fun `C2-2-8 companion constants have expected values`() {
        assertEquals(0.85f, LlmBenchmarkResult.MIN_STRICT_PASS_RATE, 0.0001f)
        assertEquals(0.01f, LlmBenchmarkResult.MAX_POLICY_VIOLATION_RATE, 0.0001f)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.8: isProductionReady — new gates
    // ══════════════════════════════════════════════════════════

    @Test
    fun `isProductionReady false when schemaComplianceRate below threshold`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.50f, 0.9f, 0, 0.8, 0, 0),  // 50% < 85% threshold
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be ready with 50% compliance (< 85%)", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when schemaComplianceRate at 84 percent`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.84f, 0.9f, 0, 0.8, 0, 0),  // 84% < 85%
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be ready at 84% compliance", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when policyViolationRate above threshold`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.95f, 0.9f, 5, 0.8, 0, 0),  // 5/20 = 25% > 1%
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be ready with 25% policy violations (> 1%)", result.isProductionReady)
    }

    @Test
    fun `isProductionReady false when exactly 1 violation over threshold`() {
        // 1 violation in 20 runs = 5% > 1%
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.95f, 0.9f, 1, 0.8, 0, 0),  // 1/20 = 5% > 1%
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertFalse("Should NOT be ready with 1 violation in 20 runs (5% > 1%)", result.isProductionReady)
    }

    @Test
    fun `isProductionReady true at exact thresholds`() {
        // 85% compliance, 0 violations → should pass
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 20,
            latency = LatencyMetrics(100, 50, 200, 100, 180, 190, 30, 10f),
            stability = StabilityMetrics(20, 20, 0, 0, 0),
            quality = QualityMetrics(0.85f, 0.9f, 0, 0.8, 0, 0),  // exactly 85%
            pipeline = PipelineMetrics(1f, 1f, 0.9f, 0.1f, 0.1f),
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 1000,
            stopFailureRate = 0f
        )
        assertTrue("Should be ready at exactly 85% compliance + 0 violations", result.isProductionReady)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.8: summary contains busyRate percentage
    // ══════════════════════════════════════════════════════════

    @Test
    fun `summary contains busyRate percentage`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 10,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(10, 8, 0, 0, 0, busyCount = 2),
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        // busyRate = 2/10 = 20% — summary should contain the busy line with a percent sign
        val busyLine = result.summary.lines().find { it.contains("Busy") }
        assertNotNull("Summary should have a Busy line", busyLine)
        assertTrue("Busy line should contain %", busyLine!!.contains("%"))
        assertTrue("Busy line should contain count 2", busyLine.contains("2"))
    }

    @Test
    fun `summary does not contain busy line when busyCount zero`() {
        val result = LlmBenchmarkResult(
            modelId = "test",
            modelVersion = "1.0",
            runtimeId = "fake",
            totalRuns = 10,
            latency = LatencyMetrics.EMPTY,
            stability = StabilityMetrics(10, 10, 0, 0, 0, busyCount = 0),
            quality = QualityMetrics.EMPTY,
            pipeline = PipelineMetrics.EMPTY,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            startedAt = 0,
            completedAt = 0
        )
        assertFalse("Summary should NOT mention Busy when count is 0", result.summary.contains("Busy"))
    }
}
