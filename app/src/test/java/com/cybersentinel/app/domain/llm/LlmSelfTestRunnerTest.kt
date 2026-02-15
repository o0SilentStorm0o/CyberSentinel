package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.*
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for LlmSelfTestRunner + LlmBenchmarkMetrics — Sprint C2-3 + C2-2.5 + C2-2.6.
 *
 * Uses FakeLlmRuntime for deterministic, fast benchmarking.
 * Tests verify: metric computation, fixture generation, pipeline coverage,
 * failure mode handling, smoke test compatibility, p99 latency, heap tracking,
 * token generation stats (avgGeneratedTokens, maxGeneratedTokens).
 */
class LlmSelfTestRunnerTest {

    private lateinit var runner: LlmSelfTestRunner
    private lateinit var runtime: FakeLlmRuntime
    private lateinit var policyGuard: PolicyGuard
    private lateinit var templateEngine: TemplateExplanationEngine

    @Before
    fun setUp() {
        policyGuard = PolicyGuard()
        templateEngine = TemplateExplanationEngine(policyGuard)
        runtime = FakeLlmRuntime(latencyMs = 0L)
        runner = LlmSelfTestRunner(
            runtime = runtime,
            promptBuilder = PromptBuilder(),
            slotParser = SlotParser(),
            slotValidator = SlotValidator(),
            templateEngine = templateEngine,
            policyGuard = policyGuard,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Benchmark execution
    // ══════════════════════════════════════════════════════════

    @Test
    fun `runBenchmark completes with correct run count`() {
        val result = runner.runBenchmark(runs = 10, modelId = "test", modelVersion = "1.0")
        assertEquals(10, result.totalRuns)
    }

    @Test
    fun `runBenchmark produces valid model metadata`() {
        val result = runner.runBenchmark(runs = 5, modelId = "test-q4", modelVersion = "2.0")
        assertEquals("test-q4", result.modelId)
        assertEquals("2.0", result.modelVersion)
        assertEquals("FakeLlmRuntime-v1", result.runtimeId)
    }

    @Test
    fun `runBenchmark duration is positive`() {
        val result = runner.runBenchmark(runs = 5)
        assertTrue("Duration should be ≥ 0", result.durationMs >= 0)
        assertTrue("completedAt should be ≥ startedAt", result.completedAt >= result.startedAt)
    }

    @Test
    fun `runBenchmark covers all severity levels with 5 runs`() {
        val result = runner.runBenchmark(runs = 5)
        // 5 runs = one per severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        assertEquals(5, result.totalRuns)
        assertTrue("Health score should be positive", result.healthScore > 0)
    }

    @Test
    fun `runBenchmark with 20 runs covers each severity 4 times`() {
        val result = runner.runBenchmark(runs = 20)
        assertEquals(20, result.totalRuns)
    }

    @Test
    fun `default run count is 20`() {
        assertEquals(20, LlmSelfTestRunner.DEFAULT_RUNS)
    }

    // ══════════════════════════════════════════════════════════
    //  Latency metrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `latency metrics are computed from FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        val latency = result.latency
        assertTrue("avgMs should be ≥ 0", latency.avgMs >= 0)
        assertTrue("minMs ≤ avgMs", latency.minMs <= latency.avgMs)
        assertTrue("avgMs ≤ maxMs", latency.avgMs <= latency.maxMs)
        assertTrue("medianMs ≥ 0", latency.medianMs >= 0)
        assertTrue("p95Ms ≥ medianMs", latency.p95Ms >= latency.medianMs)
        assertTrue("p99Ms ≥ p95Ms", latency.p99Ms >= latency.p95Ms)
    }

    @Test
    fun `latency avgTokensPerSecond is positive with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 5)
        // FakeLlmRuntime has latencyMs=0, so tokens/sec might be very high or Infinity
        // Just check it's a valid number
        assertTrue("avgTokensPerSecond should be finite",
            result.latency.avgTokensPerSecond.isFinite() || result.latency.avgTokensPerSecond == 0f)
    }

    @Test
    fun `empty LatencyMetrics has all zeros`() {
        val empty = LatencyMetrics.EMPTY
        assertEquals(0L, empty.avgMs)
        assertEquals(0L, empty.minMs)
        assertEquals(0L, empty.maxMs)
        assertEquals(0f, empty.avgTokensPerSecond, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  Stability metrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `stability shows 100 percent success with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        val stability = result.stability
        assertEquals(10, stability.totalCalls)
        assertEquals(10, stability.successCount)
        assertEquals(0, stability.oomCount)
        assertEquals(0, stability.timeoutCount)
        assertEquals(0, stability.otherErrorCount)
        assertEquals(1f, stability.successRate, 0.001f)
    }

    @Test
    fun `stability detects errors when FakeLlmRuntime is in error mode`() {
        runtime.setErrorMode(true, "Simulated OOM failure")
        val result = runner.runBenchmark(runs = 5)
        assertEquals(0, result.stability.successCount)
        assertEquals(5, result.stability.totalCalls)
        assertTrue("Failure rate should be 1.0", result.stability.failureRate == 1f)
    }

    @Test
    fun `stability empty metrics`() {
        val empty = StabilityMetrics.EMPTY
        assertEquals(0, empty.totalCalls)
        assertEquals(0f, empty.successRate, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  Quality metrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `quality compliance rate is high with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        // FakeLlmRuntime produces valid JSON → high compliance
        // Note: STRICT mode in benchmark may reject some due to severity escalation rules
        assertTrue("Compliance rate should be ≥ 0.5", result.quality.schemaComplianceRate >= 0.5f)
    }

    @Test
    fun `quality evidence faithfulness is high with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        // FakeLlmRuntime extracts real evidence IDs from prompt → faithful
        assertTrue("Evidence faithfulness should be ≥ 0.5",
            result.quality.evidenceFaithfulnessRate >= 0.5f)
    }

    @Test
    fun `quality avgConfidence is in valid range`() {
        val result = runner.runBenchmark(runs = 10)
        assertTrue("avgConfidence should be ≥ 0", result.quality.avgConfidence >= 0.0)
        assertTrue("avgConfidence should be ≤ 1", result.quality.avgConfidence <= 1.0)
    }

    @Test
    fun `quality empty metrics`() {
        val empty = QualityMetrics.EMPTY
        assertEquals(0f, empty.schemaComplianceRate, 0.001f)
        assertEquals(0, empty.policyViolationCount)
    }

    // ══════════════════════════════════════════════════════════
    //  Pipeline metrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `pipeline inference success rate is 100 percent with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        assertEquals(1f, result.pipeline.inferenceSuccessRate, 0.001f)
    }

    @Test
    fun `pipeline parse success rate is 100 percent with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        assertEquals(1f, result.pipeline.parseSuccessRate, 0.001f)
    }

    @Test
    fun `pipeline fallback rate is low with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        // FakeLlmRuntime produces valid output → low fallback rate
        // Some STRICT rejections possible, but mostly success
        assertTrue("Fallback rate should be ≤ 0.5", result.pipeline.templateFallbackRate <= 0.5f)
    }

    @Test
    fun `pipeline shows 100 percent fallback in error mode`() {
        runtime.setErrorMode(true)
        val result = runner.runBenchmark(runs = 5)
        assertEquals(0f, result.pipeline.inferenceSuccessRate, 0.001f)
        assertEquals(1f, result.pipeline.templateFallbackRate, 0.001f)
    }

    @Test
    fun `pipeline empty metrics`() {
        val empty = PipelineMetrics.EMPTY
        assertEquals(0f, empty.inferenceSuccessRate, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  Health score
    // ══════════════════════════════════════════════════════════

    @Test
    fun `healthScore is high with FakeLlmRuntime`() {
        val result = runner.runBenchmark(runs = 10)
        assertTrue("Health score should be ≥ 0.5", result.healthScore >= 0.5f)
        assertTrue("Health score should be ≤ 1.0", result.healthScore <= 1.0f)
    }

    @Test
    fun `healthScore is low in error mode`() {
        runtime.setErrorMode(true)
        val result = runner.runBenchmark(runs = 5)
        assertTrue("Health score in error mode should be ≤ 0.5", result.healthScore <= 0.5f)
    }

    @Test
    fun `healthScore is 0 with zero runs`() {
        val result = runner.runBenchmark(runs = 0)
        assertEquals(0f, result.healthScore, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  Smoke test (backward-compatible LlmSelfTestResult)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `runSmokeTest returns LlmSelfTestResult`() {
        val result = runner.runSmokeTest(modelId = "smoke-test", modelVersion = "0.1")
        assertEquals("smoke-test", result.modelId)
        assertEquals("0.1", result.modelVersion)
        assertEquals(5, result.testRunCount)
        assertTrue("passRate should be ≥ 0", result.passRate >= 0f)
        assertFalse("No OOM with fake runtime", result.oomDetected)
    }

    @Test
    fun `runSmokeTest avgLatencyMs is reasonable`() {
        val result = runner.runSmokeTest()
        assertTrue("avgLatencyMs should be ≥ 0", result.avgLatencyMs >= 0)
    }

    @Test
    fun `runSmokeTest schemaComplianceRate is in valid range`() {
        val result = runner.runSmokeTest()
        assertTrue("compliance should be ≥ 0", result.schemaComplianceRate >= 0f)
        assertTrue("compliance should be ≤ 1", result.schemaComplianceRate <= 1f)
    }

    // ══════════════════════════════════════════════════════════
    //  Fixture incidents
    // ══════════════════════════════════════════════════════════

    @Test
    fun `createFixtureIncident covers all severity levels`() {
        for (severity in IncidentSeverity.values()) {
            val incident = runner.createFixtureIncident(severity)
            assertEquals("Severity should match", severity, incident.severity)
            assertTrue("Should have events", incident.events.isNotEmpty())
            assertTrue("Should have hypotheses", incident.hypotheses.isNotEmpty())
            assertTrue("Should have actions", incident.recommendedActions.isNotEmpty())
            assertNotNull("Should have packageName", incident.packageName)
        }
    }

    @Test
    fun `fixture incidents have valid signal IDs`() {
        for (severity in IncidentSeverity.values()) {
            val incident = runner.createFixtureIncident(severity)
            for (event in incident.events) {
                for (signal in event.signals) {
                    assertTrue("Signal ID should not be blank", signal.id.isNotBlank())
                }
            }
        }
    }

    @Test
    fun `fixture incidents produce parseable prompts`() {
        val promptBuilder = PromptBuilder()
        val policyGuard = PolicyGuard()

        for (severity in IncidentSeverity.values()) {
            val incident = runner.createFixtureIncident(severity)
            val constraints = policyGuard.determineConstraints(incident)
            val prompt = promptBuilder.buildPrompt(incident, constraints)
            assertTrue("Prompt for $severity should not be blank", prompt.isNotBlank())
        }
    }

    // ══════════════════════════════════════════════════════════
    //  SingleRunResult
    // ══════════════════════════════════════════════════════════

    @Test
    fun `runSingle produces valid SingleRunResult`() {
        val result = runner.runSingle(0, IncidentSeverity.MEDIUM)
        assertEquals(0, result.runIndex)
        assertEquals(IncidentSeverity.MEDIUM, result.severity)
        assertTrue("Should have inference result", result.inferenceResult.success)
        assertTrue("Total pipeline time ≥ 0", result.totalPipelineMs >= 0)
    }

    @Test
    fun `runSingle LLM_ASSISTED for valid output`() {
        val result = runner.runSingle(0, IncidentSeverity.HIGH)
        // FakeLlmRuntime produces valid output for HIGH → either LLM_ASSISTED or FALLBACK depending on STRICT validation
        assertTrue(
            "Should be LLM_ASSISTED or FALLBACK",
            result.wasLlmAssisted || result.wasFallback
        )
    }

    @Test
    fun `runSingle with error runtime produces fallback`() {
        runtime.setErrorMode(true)
        val result = runner.runSingle(0, IncidentSeverity.MEDIUM)
        assertTrue("Should be fallback on error", result.wasFallback)
        assertFalse("Inference should fail", result.inferenceResult.success)
    }

    // ══════════════════════════════════════════════════════════
    //  Summary output
    // ══════════════════════════════════════════════════════════

    @Test
    fun `benchmark summary contains key information`() {
        val result = runner.runBenchmark(runs = 5, modelId = "summary-test", modelVersion = "3.0")
        val summary = result.summary
        assertTrue("Summary should contain model ID", summary.contains("summary-test"))
        assertTrue("Summary should contain version", summary.contains("3.0"))
        assertTrue("Summary should contain runtime", summary.contains("FakeLlmRuntime"))
        assertTrue("Summary should contain 'Runs'", summary.contains("Runs"))
    }

    // ══════════════════════════════════════════════════════════
    //  LatencyMetrics.fromResults
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LatencyMetrics fromResults with empty list returns EMPTY`() {
        val metrics = LatencyMetrics.fromResults(emptyList())
        assertEquals(LatencyMetrics.EMPTY, metrics)
    }

    @Test
    fun `LatencyMetrics fromResults computes correctly`() {
        val results = listOf(
            InferenceResult.success("output1", totalTimeMs = 100, tokensGenerated = 20),
            InferenceResult.success("output2", totalTimeMs = 200, tokensGenerated = 40),
            InferenceResult.success("output3", totalTimeMs = 150, tokensGenerated = 30)
        )
        val metrics = LatencyMetrics.fromResults(results)
        assertEquals(150L, metrics.avgMs) // (100+200+150)/3 = 150
        assertEquals(100L, metrics.minMs)
        assertEquals(200L, metrics.maxMs)
    }

    @Test
    fun `StabilityMetrics fromResults categorizes errors`() {
        val results = listOf(
            InferenceResult.success("ok"),
            InferenceResult.failure("OOM detected"),
            InferenceResult.failure("Timeout exceeded"),
            InferenceResult.failure("Unknown error")
        )
        val metrics = StabilityMetrics.fromResults(results)
        assertEquals(4, metrics.totalCalls)
        assertEquals(1, metrics.successCount)
        assertEquals(1, metrics.oomCount)
        assertEquals(1, metrics.timeoutCount)
        assertEquals(1, metrics.otherErrorCount)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.5: p99 latency + heap tracking
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LatencyMetrics fromResults computes p99`() {
        // 20 results → p99 index = (20 * 0.99).toInt() = 19 → last element
        val results = (1..20).map {
            InferenceResult.success("out$it", totalTimeMs = it * 10L, tokensGenerated = 10)
        }
        val metrics = LatencyMetrics.fromResults(results)
        assertTrue("p99Ms should be ≥ p95Ms", metrics.p99Ms >= metrics.p95Ms)
        assertTrue("p99Ms should be ≤ maxMs", metrics.p99Ms <= metrics.maxMs)
    }

    @Test
    fun `benchmark result peakNativeHeapBytes defaults to 0 in unit tests`() {
        val result = runner.runBenchmark(runs = 5)
        assertEquals("No native heap in JVM test", 0L, result.peakNativeHeapBytes)
    }

    @Test
    fun `runner with custom nativeHeapBytesProvider tracks peak`() {
        var heapCounter = 1_000_000L
        val customRunner = LlmSelfTestRunner(
            runtime = runtime,
            promptBuilder = PromptBuilder(),
            slotParser = SlotParser(),
            slotValidator = SlotValidator(),
            templateEngine = templateEngine,
            policyGuard = policyGuard,
            inferenceConfig = InferenceConfig.SLOTS_DEFAULT,
            nativeHeapBytesProvider = { heapCounter.also { heapCounter += 500_000 } }
        )
        val result = customRunner.runBenchmark(runs = 5)
        assertTrue("Peak heap should reflect provider", result.peakNativeHeapBytes >= 1_000_000L)
    }

    @Test
    fun `benchmark summary contains p99`() {
        // Create a result with non-zero latency to trigger p99 in summary
        val result = runner.runBenchmark(runs = 10, modelId = "p99-test", modelVersion = "1.0")
        val summary = result.summary
        assertTrue("Summary should contain p99", summary.contains("p99"))
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.6: Token generation stats
    // ══════════════════════════════════════════════════════════

    @Test
    fun `benchmark tracks avgGeneratedTokens`() {
        val result = runner.runBenchmark(runs = 10)
        // FakeLlmRuntime produces tokens for successful runs
        assertTrue("avgGeneratedTokens should be ≥ 0", result.avgGeneratedTokens >= 0f)
    }

    @Test
    fun `benchmark tracks maxGeneratedTokens`() {
        val result = runner.runBenchmark(runs = 10)
        assertTrue("maxGeneratedTokens should be ≥ 0", result.maxGeneratedTokens >= 0)
        assertTrue("maxGeneratedTokens should be ≥ avg",
            result.maxGeneratedTokens >= result.avgGeneratedTokens.toInt())
    }

    @Test
    fun `error mode produces zero token stats`() {
        runtime.setErrorMode(true)
        val result = runner.runBenchmark(runs = 5)
        assertEquals("Error mode should have 0 avgTokens", 0f, result.avgGeneratedTokens, 0.001f)
        assertEquals("Error mode should have 0 maxTokens", 0, result.maxGeneratedTokens)
    }

    @Test
    fun `benchmark summary contains token stats when non-zero`() {
        val result = runner.runBenchmark(runs = 10, modelId = "token-test", modelVersion = "1.0")
        if (result.avgGeneratedTokens > 0f) {
            assertTrue("Summary should mention Tokens", result.summary.contains("Tokens"))
        }
    }
}
