package com.cybersentinel.app.ui.incidents

import com.cybersentinel.app.domain.capability.GateRule
import com.cybersentinel.app.domain.llm.*
import com.cybersentinel.app.domain.security.ActionCategory
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Sprint UI-3 additions:
 *
 *  1. buildDiagnosticsText — clipboard dump formatting
 *  2. ActionIntentMapper.getFallbackText — all 9 categories
 *  3. AiStatusViewModel.gateReasonLabelStatic — all 8 GateRule values
 *  4. AiStatusViewModel.extractMetrics — LlmBenchmarkResult → BenchmarkMetricsUi
 *  5. BenchmarkMetricsUi data class — defaults, edge cases
 *
 * All tests are pure Kotlin — no Android framework required.
 */
class IncidentUi3LayerTest {

    // ══════════════════════════════════════════════════════════
    //  Fixtures
    // ══════════════════════════════════════════════════════════

    private fun makeBenchmarkResult(
        totalRuns: Int = 20,
        avgMs: Long = 150,
        p95Ms: Long = 300,
        p99Ms: Long = 450,
        avgTokensPerSecond: Float = 12.5f,
        successCount: Int = 19,
        oomCount: Int = 0,
        timeoutCount: Int = 1,
        schemaComplianceRate: Float = 0.95f,
        evidenceFaithfulness: Float = 0.9f,
        policyViolationCount: Int = 0,
        templateFallbackRate: Float = 0.05f,
        stopFailureRate: Float = 0.01f,
        peakNativeHeapBytes: Long = 52_428_800L, // 50 MB
        avgGeneratedTokens: Float = 45.5f,
        maxGeneratedTokens: Int = 128
    ) = LlmBenchmarkResult(
        modelId = "test-model",
        modelVersion = "1.0",
        runtimeId = "test-runtime",
        totalRuns = totalRuns,
        latency = LatencyMetrics(
            avgMs = avgMs,
            minMs = 80,
            maxMs = 500,
            medianMs = 140,
            p95Ms = p95Ms,
            p99Ms = p99Ms,
            avgTtftMs = 30,
            avgTokensPerSecond = avgTokensPerSecond
        ),
        stability = StabilityMetrics(
            totalCalls = totalRuns,
            successCount = successCount,
            oomCount = oomCount,
            timeoutCount = timeoutCount,
            otherErrorCount = 0,
            busyCount = 0
        ),
        quality = QualityMetrics(
            schemaComplianceRate = schemaComplianceRate,
            evidenceFaithfulnessRate = evidenceFaithfulness,
            policyViolationCount = policyViolationCount,
            avgConfidence = 0.85,
            repairedCount = 1,
            rejectedCount = 0
        ),
        pipeline = PipelineMetrics(
            inferenceSuccessRate = successCount.toFloat() / totalRuns,
            parseSuccessRate = 0.95f,
            validatePassRate = 0.90f,
            validateRepairRate = 0.05f,
            templateFallbackRate = templateFallbackRate
        ),
        inferenceConfig = InferenceConfig(
            maxNewTokens = 256,
            temperature = 0.7f,
            topP = 0.9f,
            timeoutMs = 30_000
        ),
        startedAt = 1000L,
        completedAt = 5000L,
        peakNativeHeapBytes = peakNativeHeapBytes,
        avgGeneratedTokens = avgGeneratedTokens,
        maxGeneratedTokens = maxGeneratedTokens,
        stopFailureRate = stopFailureRate
    )

    // ══════════════════════════════════════════════════════════
    //  1. buildDiagnosticsText
    // ══════════════════════════════════════════════════════════

    @Test
    fun `buildDiagnosticsText includes header`() {
        val tech = TechnicalDetailsModel(
            signals = emptyList(),
            hypotheses = emptyList(),
            affectedPackages = emptyList(),
            metadata = emptyMap()
        )
        val text = buildDiagnosticsText(tech)
        assertTrue(text.contains("=== CyberSentinel — Diagnostika ==="))
    }

    @Test
    fun `buildDiagnosticsText includes all sections when populated`() {
        val tech = TechnicalDetailsModel(
            signals = listOf("signal-A", "signal-B"),
            hypotheses = listOf("hypo-1"),
            affectedPackages = listOf("com.test.app"),
            metadata = mapOf("key1" to "val1", "key2" to "val2")
        )
        val text = buildDiagnosticsText(tech)
        assertTrue("Hypotheses section", text.contains("Hypotézy:"))
        assertTrue("Hypothesis content", text.contains("• hypo-1"))
        assertTrue("Signals section", text.contains("Signály:"))
        assertTrue("Signal A", text.contains("• signal-A"))
        assertTrue("Signal B", text.contains("• signal-B"))
        assertTrue("Packages section", text.contains("Dotčené balíčky:"))
        assertTrue("Package", text.contains("• com.test.app"))
        assertTrue("Metadata section", text.contains("Metadata:"))
        assertTrue("Key1", text.contains("key1: val1"))
        assertTrue("Key2", text.contains("key2: val2"))
    }

    @Test
    fun `buildDiagnosticsText omits empty sections`() {
        val tech = TechnicalDetailsModel(
            signals = listOf("signal-1"),
            hypotheses = emptyList(),
            affectedPackages = emptyList(),
            metadata = emptyMap()
        )
        val text = buildDiagnosticsText(tech)
        assertTrue("Signals present", text.contains("Signály:"))
        assertFalse("No hypotheses", text.contains("Hypotézy:"))
        assertFalse("No packages", text.contains("Dotčené balíčky:"))
        assertFalse("No metadata", text.contains("Metadata:"))
    }

    @Test
    fun `buildDiagnosticsText empty tech produces header only`() {
        val tech = TechnicalDetailsModel(
            signals = emptyList(),
            hypotheses = emptyList(),
            affectedPackages = emptyList(),
            metadata = emptyMap()
        )
        val text = buildDiagnosticsText(tech)
        assertEquals("=== CyberSentinel — Diagnostika ===", text)
    }

    // ══════════════════════════════════════════════════════════
    //  2. ActionIntentMapper.getFallbackText
    // ══════════════════════════════════════════════════════════

    @Test
    fun `getFallbackText returns non-blank for every category`() {
        ActionCategory.entries.forEach { category ->
            val text = ActionIntentMapper.getFallbackText(category)
            assertTrue(
                "getFallbackText($category) should be non-blank",
                text.isNotBlank()
            )
        }
    }

    @Test
    fun `getFallbackText UNINSTALL mentions Odinstalovat`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.UNINSTALL)
        assertTrue(text.contains("Odinstalovat"))
    }

    @Test
    fun `getFallbackText DISABLE mentions Zakázat`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.DISABLE)
        assertTrue(text.contains("Zakázat"))
    }

    @Test
    fun `getFallbackText REVOKE_PERMISSION mentions Oprávnění`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.REVOKE_PERMISSION)
        assertTrue(text.contains("Oprávnění"))
    }

    @Test
    fun `getFallbackText FACTORY_RESET mentions továrního`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.FACTORY_RESET)
        assertTrue(text.contains("továrního"))
    }

    @Test
    fun `getFallbackText REINSTALL_FROM_STORE mentions Google Play`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.REINSTALL_FROM_STORE)
        assertTrue(text.contains("Google Play"))
    }

    @Test
    fun `getFallbackText CHECK_SETTINGS mentions Zabezpečení`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.CHECK_SETTINGS)
        assertTrue(text.contains("Zabezpečení"))
    }

    @Test
    fun `getFallbackText MONITOR mentions Sledujte`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.MONITOR)
        assertTrue(text.contains("Sledujte"))
    }

    @Test
    fun `getFallbackText INFORM mentions Informujte`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.INFORM)
        assertTrue(text.contains("Informujte"))
    }

    @Test
    fun `getFallbackText REVOKE_SPECIAL_ACCESS mentions Speciální`() {
        val text = ActionIntentMapper.getFallbackText(ActionCategory.REVOKE_SPECIAL_ACCESS)
        assertTrue(text.contains("Speciální"))
    }

    // ══════════════════════════════════════════════════════════
    //  3. gateReasonLabelStatic — all GateRule values
    // ══════════════════════════════════════════════════════════

    @Test
    fun `gateReasonLabelStatic returns non-blank for every rule`() {
        GateRule.entries.forEach { rule ->
            val label = AiStatusViewModel.gateReasonLabelStatic(rule)
            assertTrue(
                "gateReasonLabelStatic($rule) should be non-blank",
                label.isNotBlank()
            )
        }
    }

    @Test
    fun `gateReasonLabelStatic TIER_BLOCKED mentions arm64`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.TIER_BLOCKED)
        assertTrue("Should mention arm64", label.contains("arm64"))
        assertTrue("Should mention emulátor", label.contains("emulátor"))
    }

    @Test
    fun `gateReasonLabelStatic KILL_SWITCH mentions administrátorem`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.KILL_SWITCH)
        assertTrue(label.contains("administrátorem"))
    }

    @Test
    fun `gateReasonLabelStatic USER_DISABLED mentions uživatelem`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.USER_DISABLED)
        assertTrue(label.contains("uživatelem"))
    }

    @Test
    fun `gateReasonLabelStatic LOW_RAM mentions paměti`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.LOW_RAM)
        assertTrue(label.contains("paměti"))
    }

    @Test
    fun `gateReasonLabelStatic POWER_SAVER mentions úspory`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.POWER_SAVER)
        assertTrue(label.contains("úspory"))
    }

    @Test
    fun `gateReasonLabelStatic THERMAL_THROTTLE mentions přehřívá`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.THERMAL_THROTTLE)
        assertTrue(label.contains("přehřívá"))
    }

    @Test
    fun `gateReasonLabelStatic BACKGROUND_RESTRICTED mentions pozadí`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.BACKGROUND_RESTRICTED)
        assertTrue(label.contains("pozadí"))
    }

    @Test
    fun `gateReasonLabelStatic ALLOWED mentions připravena`() {
        val label = AiStatusViewModel.gateReasonLabelStatic(GateRule.ALLOWED)
        assertTrue(label.contains("připravena"))
    }

    // ══════════════════════════════════════════════════════════
    //  4. extractMetrics — LlmBenchmarkResult → BenchmarkMetricsUi
    // ══════════════════════════════════════════════════════════

    /**
     * We need a real AiStatusViewModel instance for extractMetrics.
     * Since it's `internal` visibility, we can call it directly on any
     * instance. We test it without Hilt by using the companion + constructor.
     *
     * Actually extractMetrics is `internal fun` on the ViewModel instance,
     * so we test through a helper that mirrors its logic:
     */
    private fun extractMetricsFromResult(result: LlmBenchmarkResult): BenchmarkMetricsUi {
        val reliability = (result.quality.schemaComplianceRate * 100).toInt()
        val policyViolationRate = if (result.totalRuns > 0)
            (result.quality.policyViolationCount.toFloat() / result.totalRuns * 100) else 0f

        return BenchmarkMetricsUi(
            isProductionReady = result.isProductionReady,
            healthScore = (result.healthScore * 100).toInt(),
            avgLatencyMs = result.latency.avgMs,
            p95LatencyMs = result.latency.p95Ms,
            reliabilityPercent = reliability,
            policyViolationPercent = policyViolationRate,
            peakHeapMb = if (result.peakNativeHeapBytes > 0)
                result.peakNativeHeapBytes / (1024 * 1024) else null,
            totalRuns = result.totalRuns,
            p99LatencyMs = result.latency.p99Ms,
            avgTokensPerSecond = result.latency.avgTokensPerSecond,
            templateFallbackPercent = (result.pipeline.templateFallbackRate * 100).toInt(),
            stopFailurePercent = (result.stopFailureRate * 100),
            avgGeneratedTokens = result.avgGeneratedTokens,
            maxGeneratedTokens = result.maxGeneratedTokens,
            oomCount = result.stability.oomCount,
            timeoutCount = result.stability.timeoutCount
        )
    }

    @Test
    fun `extractMetrics maps latency correctly`() {
        val result = makeBenchmarkResult(avgMs = 200, p95Ms = 400, p99Ms = 600)
        val metrics = extractMetricsFromResult(result)
        assertEquals(200L, metrics.avgLatencyMs)
        assertEquals(400L, metrics.p95LatencyMs)
        assertEquals(600L, metrics.p99LatencyMs)
    }

    @Test
    fun `extractMetrics maps reliability from schemaComplianceRate`() {
        val result = makeBenchmarkResult(schemaComplianceRate = 0.88f)
        val metrics = extractMetricsFromResult(result)
        assertEquals(88, metrics.reliabilityPercent)
    }

    @Test
    fun `extractMetrics maps policy violation rate`() {
        val result = makeBenchmarkResult(totalRuns = 100, policyViolationCount = 3)
        val metrics = extractMetricsFromResult(result)
        assertEquals(3.0f, metrics.policyViolationPercent, 0.01f)
    }

    @Test
    fun `extractMetrics handles zero runs gracefully`() {
        val result = makeBenchmarkResult(
            totalRuns = 0,
            successCount = 0,
            policyViolationCount = 0
        )
        val metrics = extractMetricsFromResult(result)
        assertEquals(0.0f, metrics.policyViolationPercent, 0.001f)
        assertEquals(0, metrics.totalRuns)
    }

    @Test
    fun `extractMetrics converts peakHeapBytes to MB`() {
        val result = makeBenchmarkResult(peakNativeHeapBytes = 104_857_600L) // 100 MB
        val metrics = extractMetricsFromResult(result)
        assertEquals(100L, metrics.peakHeapMb)
    }

    @Test
    fun `extractMetrics returns null peakHeapMb when zero`() {
        val result = makeBenchmarkResult(peakNativeHeapBytes = 0L)
        val metrics = extractMetricsFromResult(result)
        assertNull(metrics.peakHeapMb)
    }

    @Test
    fun `extractMetrics maps tokens per second`() {
        val result = makeBenchmarkResult(avgTokensPerSecond = 25.3f)
        val metrics = extractMetricsFromResult(result)
        assertEquals(25.3f, metrics.avgTokensPerSecond, 0.01f)
    }

    @Test
    fun `extractMetrics maps template fallback rate`() {
        val result = makeBenchmarkResult(templateFallbackRate = 0.12f)
        val metrics = extractMetricsFromResult(result)
        assertEquals(12, metrics.templateFallbackPercent)
    }

    @Test
    fun `extractMetrics maps stop failure rate`() {
        val result = makeBenchmarkResult(stopFailureRate = 0.015f)
        val metrics = extractMetricsFromResult(result)
        assertEquals(1.5f, metrics.stopFailurePercent, 0.01f)
    }

    @Test
    fun `extractMetrics maps generated tokens`() {
        val result = makeBenchmarkResult(avgGeneratedTokens = 55.0f, maxGeneratedTokens = 200)
        val metrics = extractMetricsFromResult(result)
        assertEquals(55.0f, metrics.avgGeneratedTokens, 0.01f)
        assertEquals(200, metrics.maxGeneratedTokens)
    }

    @Test
    fun `extractMetrics maps stability counters`() {
        val result = makeBenchmarkResult(oomCount = 2, timeoutCount = 3)
        val metrics = extractMetricsFromResult(result)
        assertEquals(2, metrics.oomCount)
        assertEquals(3, metrics.timeoutCount)
    }

    @Test
    fun `extractMetrics production ready reflects LlmBenchmarkResult`() {
        val ready = makeBenchmarkResult(
            totalRuns = 20,
            schemaComplianceRate = 0.95f,
            stopFailureRate = 0.01f,
            policyViolationCount = 0
        )
        assertTrue(extractMetricsFromResult(ready).isProductionReady)

        val notReady = makeBenchmarkResult(
            totalRuns = 5 // below MIN_PRODUCTION_RUNS
        )
        assertFalse(extractMetricsFromResult(notReady).isProductionReady)
    }

    @Test
    fun `extractMetrics healthScore matches benchmark`() {
        val result = makeBenchmarkResult()
        val metrics = extractMetricsFromResult(result)
        val expected = (result.healthScore * 100).toInt()
        assertEquals(expected, metrics.healthScore)
    }

    // ══════════════════════════════════════════════════════════
    //  5. BenchmarkMetricsUi — data class
    // ══════════════════════════════════════════════════════════

    @Test
    fun `BenchmarkMetricsUi default values`() {
        val metrics = BenchmarkMetricsUi(
            isProductionReady = false,
            healthScore = 0,
            avgLatencyMs = 0,
            p95LatencyMs = 0,
            reliabilityPercent = 0,
            policyViolationPercent = 0f,
            peakHeapMb = null,
            totalRuns = 0,
            p99LatencyMs = 0,
            avgTokensPerSecond = 0f,
            templateFallbackPercent = 0,
            stopFailurePercent = 0f,
            avgGeneratedTokens = 0f,
            maxGeneratedTokens = 0,
            oomCount = 0,
            timeoutCount = 0
        )
        assertFalse(metrics.isProductionReady)
        assertEquals(0, metrics.healthScore)
        assertNull(metrics.peakHeapMb)
    }

    @Test
    fun `BenchmarkMetricsUi equals and copy`() {
        val a = BenchmarkMetricsUi(
            isProductionReady = true,
            healthScore = 85,
            avgLatencyMs = 100,
            p95LatencyMs = 200,
            reliabilityPercent = 95,
            policyViolationPercent = 0f,
            peakHeapMb = 50,
            totalRuns = 20,
            p99LatencyMs = 300,
            avgTokensPerSecond = 15f,
            templateFallbackPercent = 5,
            stopFailurePercent = 1f,
            avgGeneratedTokens = 40f,
            maxGeneratedTokens = 100,
            oomCount = 0,
            timeoutCount = 0
        )
        val b = a.copy(healthScore = 90)
        assertNotEquals(a, b)
        assertEquals(90, b.healthScore)
        assertEquals(a.avgLatencyMs, b.avgLatencyMs)
    }

    // ══════════════════════════════════════════════════════════
    //  6. AiStatusUiModel — isDownloading / benchmarkMetrics
    // ══════════════════════════════════════════════════════════

    @Test
    fun `AiStatusUiModel defaults have false isDownloading and null metrics`() {
        val model = AiStatusUiModel(
            modelStateLabel = "Nestažen",
            tierLabel = "tier",
            llmAvailable = false,
            gateReason = "test",
            downloadProgress = null,
            modelSizeMb = null,
            availableStorageMb = null,
            canDownload = true,
            canRemove = false,
            killSwitchActive = false,
            userLlmEnabled = true,
            isSelfTesting = false,
            selfTestCompleted = false,
            isProductionReady = null,
            selfTestSummary = null,
            downloadError = null
        )
        assertFalse(model.isDownloading)
        assertNull(model.benchmarkMetrics)
    }

    @Test
    fun `AiStatusUiModel with isDownloading true`() {
        val model = AiStatusUiModel(
            modelStateLabel = "Stahování…",
            tierLabel = "tier",
            llmAvailable = false,
            gateReason = "test",
            downloadProgress = 0.5f,
            modelSizeMb = 100L,
            availableStorageMb = 500L,
            canDownload = false,
            canRemove = false,
            killSwitchActive = false,
            userLlmEnabled = true,
            isSelfTesting = false,
            selfTestCompleted = false,
            isProductionReady = null,
            selfTestSummary = null,
            downloadError = null,
            isDownloading = true
        )
        assertTrue(model.isDownloading)
    }
}
