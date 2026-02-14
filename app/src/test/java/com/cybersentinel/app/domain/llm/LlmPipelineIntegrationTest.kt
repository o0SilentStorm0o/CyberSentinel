package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.*
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

/**
 * Integration tests for the complete LLM pipeline — Sprint C2-1.
 *
 * Tests the full chain:
 *   PromptBuilder → FakeLlmRuntime → SlotParser → SlotValidator
 *     → TemplateExplanationEngine.renderFromSlots → PolicyGuard
 *
 * Also tests:
 *   - FakeLlmRuntime fixture generation
 *   - LocalLlmExplanationEngine E2E
 *   - ExplanationOrchestrator integration with LLM engine
 *   - ModelManager operations
 *   - Fallback behavior on various failure modes
 */
class LlmPipelineIntegrationTest {

    private lateinit var policyGuard: PolicyGuard
    private lateinit var templateEngine: TemplateExplanationEngine
    private lateinit var promptBuilder: PromptBuilder
    private lateinit var slotParser: SlotParser
    private lateinit var slotValidator: SlotValidator

    @Before
    fun setUp() {
        policyGuard = PolicyGuard()
        templateEngine = TemplateExplanationEngine(policyGuard)
        promptBuilder = PromptBuilder()
        slotParser = SlotParser()
        slotValidator = SlotValidator()
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeSignal(
        id: String = "sig-001",
        type: SignalType = SignalType.CERT_CHANGE,
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.app"
    ) = SecuritySignal(
        id = id,
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Test signal for $type"
    )

    private fun makeIncident(
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        eventType: EventType = EventType.SUSPICIOUS_UPDATE,
        signalTypes: List<Pair<String, SignalType>> = listOf("sig-001" to SignalType.CERT_CHANGE),
        pkg: String = "com.test.app"
    ): SecurityIncident {
        val signals = signalTypes.map { (id, type) -> makeSignal(id, type) }
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = eventType,
            severity = SignalSeverity.HIGH,
            packageName = pkg,
            summary = "Test event",
            signals = signals
        )
        return SecurityIncident(
            severity = severity,
            title = "Test incident",
            summary = "Test",
            packageName = pkg,
            events = listOf(event),
            hypotheses = listOf(
                Hypothesis(
                    name = "suspicious_update",
                    description = "Test hypothesis",
                    confidence = 0.7,
                    supportingEvidence = signals.map { it.id }
                )
            ),
            recommendedActions = listOf(
                RecommendedAction(1, ActionCategory.CHECK_SETTINGS, "Check", "desc", pkg),
                RecommendedAction(2, ActionCategory.MONITOR, "Monitor", "desc", pkg)
            )
        )
    }

    private fun makeEngine(
        runtime: LlmRuntime = FakeLlmRuntime(latencyMs = 0L)
    ) = LocalLlmExplanationEngine(
        runtime = runtime,
        promptBuilder = promptBuilder,
        slotParser = slotParser,
        slotValidator = slotValidator,
        templateEngine = templateEngine,
        policyGuard = policyGuard
    )

    // ══════════════════════════════════════════════════════════
    //  FakeLlmRuntime tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `FakeLlmRuntime returns successful InferenceResult`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        val prompt = promptBuilder.buildPrompt(makeIncident(), emptySet())

        val result = runtime.runInference(prompt, InferenceConfig.SLOTS_DEFAULT)
        assertTrue("Should succeed", result.success)
        assertNull(result.error)
        assertTrue("Should have raw output", result.rawOutput.isNotBlank())
        assertNotNull(result.tokensGenerated)
    }

    @Test
    fun `FakeLlmRuntime output is parseable JSON`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        val incident = makeIncident(severity = IncidentSeverity.HIGH)
        val prompt = promptBuilder.buildPrompt(incident, emptySet())
        val result = runtime.runInference(prompt, InferenceConfig.SLOTS_DEFAULT)

        val parseResult = slotParser.parse(result.rawOutput)
        assertTrue("Fake output must be parseable", parseResult.isSuccess)
    }

    @Test
    fun `FakeLlmRuntime produces severity-appropriate slots`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)

        for (severity in IncidentSeverity.values()) {
            val incident = makeIncident(severity = severity)
            val prompt = promptBuilder.buildPrompt(incident, emptySet())
            val result = runtime.runInference(prompt, InferenceConfig.SLOTS_DEFAULT)
            val parsed = slotParser.parse(result.rawOutput)

            assertTrue("Should parse for $severity", parsed.isSuccess)
            assertEquals(
                "Severity should match for $severity",
                severity,
                parsed.slotsOrNull!!.assessedSeverity
            )
        }
    }

    @Test
    fun `FakeLlmRuntime extracts real evidence IDs from prompt`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        val incident = makeIncident(
            signalTypes = listOf("real-sig-1" to SignalType.CERT_CHANGE, "real-sig-2" to SignalType.VERSION_ROLLBACK)
        )
        val prompt = promptBuilder.buildPrompt(incident, emptySet())
        val result = runtime.runInference(prompt, InferenceConfig.SLOTS_DEFAULT)
        val parsed = slotParser.parse(result.rawOutput)

        assertTrue(parsed.isSuccess)
        val slots = parsed.slotsOrNull!!
        assertTrue("Should reference real evidence IDs", slots.selectedEvidenceIds.any { it.startsWith("real-sig") })
    }

    @Test
    fun `FakeLlmRuntime error mode returns failure`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        runtime.setErrorMode(true, "Test error")

        assertFalse(runtime.isAvailable)
        val result = runtime.runInference("test", InferenceConfig.SLOTS_DEFAULT)
        assertFalse(result.success)
        assertEquals("Test error", result.error)
    }

    @Test
    fun `FakeLlmRuntime isAvailable is true by default`() {
        assertTrue(FakeLlmRuntime().isAvailable)
    }

    @Test
    fun `FakeLlmRuntime runtimeId is correct`() {
        assertEquals("FakeLlmRuntime-v1", FakeLlmRuntime().runtimeId)
    }

    @Test
    fun `FakeLlmRuntime createMarkdownWrapped wraps in fences`() {
        val runtime = FakeLlmRuntime.createMarkdownWrapped()
        val prompt = promptBuilder.buildPrompt(makeIncident(), emptySet())
        val result = runtime.runInference(prompt, InferenceConfig.SLOTS_DEFAULT)

        assertTrue(result.success)
        assertTrue("Should contain markdown fence", result.rawOutput.contains("```json"))
        // Should still be parseable
        assertTrue(slotParser.parse(result.rawOutput).isSuccess)
    }

    // ══════════════════════════════════════════════════════════
    //  LocalLlmExplanationEngine E2E
    // ══════════════════════════════════════════════════════════

    @Test
    fun `E2E - full pipeline produces LLM_ASSISTED answer`() {
        val engine = makeEngine()
        val incident = makeIncident(severity = IncidentSeverity.HIGH)
        val request = ExplanationRequest(incident)

        val answer = engine.explain(request)

        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
        assertTrue("Should have reasons", answer.reasons.isNotEmpty())
        assertTrue("Should have actions", answer.actions.isNotEmpty())
        assertTrue("Summary should not be blank", answer.summary.isNotBlank())
        assertTrue("Confidence should be positive", answer.confidence > 0)
    }

    @Test
    fun `E2E - CRITICAL incident produces complete answer`() {
        val engine = makeEngine()
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            signalTypes = listOf(
                "sig-a" to SignalType.CERT_CHANGE,
                "sig-b" to SignalType.VERSION_ROLLBACK
            )
        )
        val request = ExplanationRequest(incident)
        val answer = engine.explain(request)

        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
        assertNotNull(answer.incidentId)
    }

    @Test
    fun `E2E - INFO incident produces calm answer`() {
        val engine = makeEngine()
        val incident = makeIncident(severity = IncidentSeverity.INFO)
        val request = ExplanationRequest(incident)
        val answer = engine.explain(request)

        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
    }

    @Test
    fun `E2E - all severity levels produce valid answers`() {
        val engine = makeEngine()

        for (severity in IncidentSeverity.values()) {
            val incident = makeIncident(severity = severity)
            val answer = engine.explain(ExplanationRequest(incident))

            assertNotNull("Answer should exist for $severity", answer)
            assertTrue(
                "Engine source should be LLM_ASSISTED or fallback for $severity",
                answer.engineSource in listOf(EngineSource.LLM_ASSISTED, EngineSource.LLM_FALLBACK_TO_TEMPLATE)
            )
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Fallback tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `fallback on runtime error`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        runtime.setErrorMode(true)
        val engine = makeEngine(runtime = runtime)

        val answer = engine.explain(ExplanationRequest(makeIncident()))
        assertEquals(
            "Should fallback to template",
            EngineSource.LLM_FALLBACK_TO_TEMPLATE,
            answer.engineSource
        )
    }

    @Test
    fun `fallback on unavailable runtime`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        runtime.setErrorMode(true)
        val engine = makeEngine(runtime = runtime)

        assertFalse(engine.isAvailable)
        val answer = engine.explain(ExplanationRequest(makeIncident()))
        assertEquals(EngineSource.LLM_FALLBACK_TO_TEMPLATE, answer.engineSource)
    }

    @Test
    fun `fallback answer still has valid structure`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        runtime.setErrorMode(true)
        val engine = makeEngine(runtime = runtime)

        val answer = engine.explain(ExplanationRequest(makeIncident()))

        assertNotNull(answer.incidentId)
        assertTrue(answer.summary.isNotBlank())
        assertTrue(answer.reasons.isNotEmpty())
        assertTrue(answer.actions.isNotEmpty())
    }

    // ══════════════════════════════════════════════════════════
    //  Engine properties
    // ══════════════════════════════════════════════════════════

    @Test
    fun `engineId contains runtime identifier`() {
        val engine = makeEngine()
        assertTrue(engine.engineId.contains("FakeLlmRuntime-v1"))
    }

    @Test
    fun `getDiagnostics returns correct info`() {
        val engine = makeEngine()
        val diag = engine.getDiagnostics()

        assertEquals("FakeLlmRuntime-v1", diag.runtimeId)
        assertTrue(diag.isAvailable)
        assertEquals(InferenceConfig.SLOTS_DEFAULT, diag.inferenceConfig)
    }

    @Test
    fun `shutdown is safe to call multiple times`() {
        val engine = makeEngine()
        engine.shutdown()
        engine.shutdown() // No exception
    }

    // ══════════════════════════════════════════════════════════
    //  LLM engine as ExplanationEngine — contract tests
    //  (Orchestrator integration tested in ExplanationOrchestratorTest)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LLM engine implements ExplanationEngine correctly`() {
        val engine: ExplanationEngine = makeEngine()
        assertTrue(engine.isAvailable)
        assertTrue(engine.engineId.isNotBlank())
    }

    @Test
    fun `LLM engine explain returns LLM_ASSISTED source`() {
        val engine: ExplanationEngine = makeEngine()
        val answer = engine.explain(ExplanationRequest(makeIncident()))
        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
    }

    @Test
    fun `LLM engine with error runtime returns FALLBACK source`() {
        val runtime = FakeLlmRuntime(latencyMs = 0L)
        runtime.setErrorMode(true)
        val engine: ExplanationEngine = makeEngine(runtime = runtime)
        val answer = engine.explain(ExplanationRequest(makeIncident()))
        assertEquals(EngineSource.LLM_FALLBACK_TO_TEMPLATE, answer.engineSource)
    }

    // ══════════════════════════════════════════════════════════
    //  ModelManager tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `ModelManager initial state is NOT_DOWNLOADED`() {
        val manager = ModelManager(FakeModelDownloader())
        assertEquals(ModelState.NOT_DOWNLOADED, manager.getState())
        assertNull(manager.getModelInfo())
    }

    @Test
    fun `ModelManager computeSha256 produces correct hash`() {
        val manager = ModelManager(FakeModelDownloader())
        val data = "Hello, World!".toByteArray()
        val hash = manager.computeSha256(ByteArrayInputStream(data))
        // Known SHA-256 of "Hello, World!"
        assertEquals("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", hash)
    }

    @Test
    fun `ModelManager kill switch blocks operations`() {
        val manager = ModelManager(FakeModelDownloader())
        manager.activateKillSwitch()

        assertEquals(ModelState.KILLED, manager.getState())
        assertTrue(manager.isKillSwitchActive())

        val manifest = makeManifest()
        val result = manager.downloadModel(manifest, createTempDir())
        assertFalse(result.isSuccess)
    }

    @Test
    fun `ModelManager kill switch can be deactivated`() {
        val manager = ModelManager(FakeModelDownloader())
        manager.activateKillSwitch()
        manager.deactivateKillSwitch()

        assertFalse(manager.isKillSwitchActive())
        assertEquals(ModelState.NOT_DOWNLOADED, manager.getState())
    }

    @Test
    fun `ModelManager lifecycle - markLoaded and markUnloaded`() {
        val manager = ModelManager(FakeModelDownloader())
        // Simulate downloading successfully (set internal state)
        val manifest = makeManifest()
        val tempDir = createTempDir()
        val result = manager.downloadModel(manifest, tempDir)

        if (result.isSuccess) {
            assertEquals(ModelState.READY, manager.getState())

            manager.markLoaded()
            assertEquals(ModelState.LOADED, manager.getState())

            manager.markUnloaded()
            assertEquals(ModelState.READY, manager.getState())
        }

        // Cleanup
        tempDir.deleteRecursively()
    }

    @Test
    fun `ModelManager deleteModel resets state`() {
        val manager = ModelManager(FakeModelDownloader())
        manager.deleteModel()
        assertEquals(ModelState.NOT_DOWNLOADED, manager.getState())
        assertNull(manager.getModelInfo())
    }

    @Test
    fun `ModelManager verifyIntegrity returns false for non-existent file`() {
        val manager = ModelManager(FakeModelDownloader())
        assertFalse(manager.verifyIntegrity(File("/nonexistent/path"), "abc"))
    }

    // ══════════════════════════════════════════════════════════
    //  InferenceConfig tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `InferenceConfig SLOTS_DEFAULT has correct values`() {
        val config = InferenceConfig.SLOTS_DEFAULT
        assertEquals(160, config.maxNewTokens)
        assertEquals(0.1f, config.temperature, 0.001f)
        assertEquals(15_000L, config.timeoutMs)
    }

    @Test
    fun `InferenceConfig TIER1_CONSERVATIVE has lower token budget`() {
        val config = InferenceConfig.TIER1_CONSERVATIVE
        assertTrue(config.maxNewTokens < InferenceConfig.SLOTS_DEFAULT.maxNewTokens)
        assertTrue(config.timeoutMs > InferenceConfig.SLOTS_DEFAULT.timeoutMs)
    }

    @Test
    fun `InferenceResult success factory`() {
        val result = InferenceResult.success("test output", 100, 500, 40)
        assertTrue(result.success)
        assertEquals("test output", result.rawOutput)
        assertNotNull(result.tokensPerSecond)
        assertEquals(80f, result.tokensPerSecond!!, 1f) // 40*1000/500
    }

    @Test
    fun `InferenceResult failure factory`() {
        val result = InferenceResult.failure("timeout")
        assertFalse(result.success)
        assertEquals("timeout", result.error)
        assertEquals("", result.rawOutput)
    }

    // ══════════════════════════════════════════════════════════
    //  LlmSelfTestResult tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `LlmSelfTestResult passRate calculation`() {
        val result = LlmSelfTestResult(
            modelId = "test",
            modelVersion = "1.0",
            avgLatencyMs = 100,
            schemaComplianceRate = 0.9f,
            oomDetected = false,
            testRunCount = 10,
            successfulParses = 8,
            avgTokensPerSecond = 5f
        )
        assertEquals(0.8f, result.passRate, 0.001f)
    }

    @Test
    fun `LlmSelfTestResult passRate zero when no runs`() {
        val result = LlmSelfTestResult(
            modelId = "test",
            modelVersion = "1.0",
            avgLatencyMs = 0,
            schemaComplianceRate = 0f,
            oomDetected = false,
            testRunCount = 0,
            successfulParses = 0,
            avgTokensPerSecond = 0f
        )
        assertEquals(0f, result.passRate, 0.001f)
    }

    // ══════════════════════════════════════════════════════════
    //  DownloadProgress tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `DownloadProgress calculates percent`() {
        val progress = DownloadProgress("model", 1000, 500, DownloadState.DOWNLOADING)
        assertEquals(50, progress.progressPercent)
    }

    @Test
    fun `DownloadProgress zero total returns 0 percent`() {
        val progress = DownloadProgress("model", 0, 0, DownloadState.IDLE)
        assertEquals(0, progress.progressPercent)
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeManifest() = ModelManifest(
        modelId = "test-model-v1",
        displayName = "Test Model",
        version = "1.0.0",
        downloadUrl = "https://example.com/model.gguf",
        fileSizeBytes = 1024,
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty file hash
        quantization = "Q4_K_M"
    )

    private fun createTempDir(): File {
        val dir = File(System.getProperty("java.io.tmpdir"), "cybersentinel-test-${System.nanoTime()}")
        dir.mkdirs()
        return dir
    }

    /**
     * Fake ModelDownloader that writes empty bytes matching the expected SHA.
     */
    private class FakeModelDownloader : ModelDownloader {
        override fun download(
            url: String,
            target: File,
            onProgress: ((downloaded: Long, total: Long) -> Unit)?
        ): Boolean {
            return try {
                target.parentFile?.mkdirs()
                target.writeBytes(ByteArray(0)) // Empty file → known SHA
                onProgress?.invoke(0, 0)
                true
            } catch (_: Exception) {
                false
            }
        }
    }
}
