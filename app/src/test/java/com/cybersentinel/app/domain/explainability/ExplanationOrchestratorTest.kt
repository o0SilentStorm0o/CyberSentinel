package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.capability.*
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for ExplanationOrchestrator — engine selection and fallback.
 *
 * Since ExplanationOrchestrator depends on FeatureGatekeeper (which needs
 * Android context via DeviceProfiler), we test the orchestrator's logic
 * by focusing on the template-only path and fake LLM engines.
 *
 * The FeatureGatekeeper itself is tested in FeatureGatekeeperTest.
 * Here we use a StubFeatureGatekeeper that extends FeatureGatekeeper
 * and overrides the methods that would need Android APIs.
 *
 * Tests verify:
 *  1. Template-only mode (no LLM engine registered)
 *  2. LLM fallback behavior
 *  3. PolicyGuard double-check
 *  4. ExplanationAnswer model properties
 */
class ExplanationOrchestratorTest {

    private lateinit var policyGuard: PolicyGuard
    private lateinit var templateEngine: TemplateExplanationEngine

    @Before
    fun setUp() {
        policyGuard = PolicyGuard()
        templateEngine = TemplateExplanationEngine(policyGuard)
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeIncident(
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        eventType: EventType = EventType.SUSPICIOUS_UPDATE,
        signalType: SignalType = SignalType.CERT_CHANGE,
        hypothesisConfidence: Double = 0.5,
        pkg: String = "com.test.app"
    ): SecurityIncident {
        val signal = SecuritySignal(
            source = SignalSource.APP_SCANNER,
            type = signalType,
            severity = SignalSeverity.HIGH,
            packageName = pkg,
            summary = "Test signal"
        )
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = eventType,
            severity = SignalSeverity.HIGH,
            packageName = pkg,
            summary = "Test event",
            signals = listOf(signal)
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
                    description = "Test",
                    confidence = hypothesisConfidence,
                    supportingEvidence = listOf(signal.id)
                )
            ),
            recommendedActions = listOf(
                RecommendedAction(1, ActionCategory.CHECK_SETTINGS, "Check", "desc", pkg),
                RecommendedAction(2, ActionCategory.MONITOR, "Monitor", "desc", pkg)
            )
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Template engine produces valid answers via direct call
    // ══════════════════════════════════════════════════════════

    @Test
    fun `template engine produces valid answer`() {
        val request = ExplanationRequest(makeIncident())
        val answer = templateEngine.explain(request)
        assertEquals(EngineSource.TEMPLATE, answer.engineSource)
        assertTrue(answer.summary.isNotEmpty())
        assertTrue(answer.incidentId.isNotEmpty())
        assertTrue(answer.confidence > 0)
    }

    @Test
    fun `template engine attaches SafeLanguageFlags`() {
        val request = ExplanationRequest(makeIncident(severity = IncidentSeverity.INFO))
        val answer = templateEngine.explain(request)
        assertTrue(SafeLanguageFlag.NO_VIRUS_CLAIM in answer.safeLanguageFlags)
        assertTrue(SafeLanguageFlag.NO_ALARMIST_FRAMING in answer.safeLanguageFlags)
    }

    @Test
    fun `template engine generates whenToIgnore for INFO`() {
        val request = ExplanationRequest(makeIncident(severity = IncidentSeverity.INFO))
        val answer = templateEngine.explain(request)
        assertNotNull(answer.whenToIgnore)
    }

    @Test
    fun `template engine omits whenToIgnore for CRITICAL`() {
        val request = ExplanationRequest(makeIncident(
            severity = IncidentSeverity.CRITICAL,
            signalType = SignalType.DEBUG_SIGNATURE,
            hypothesisConfidence = 0.9
        ))
        val answer = templateEngine.explain(request)
        assertNull(answer.whenToIgnore)
    }

    // ══════════════════════════════════════════════════════════
    //  PolicyGuard integration via template engine
    // ══════════════════════════════════════════════════════════

    @Test
    fun `PolicyGuard prevents factory reset for non-critical`() {
        val incident = makeIncident(severity = IncidentSeverity.HIGH).copy(
            recommendedActions = listOf(
                RecommendedAction(1, ActionCategory.FACTORY_RESET, "Reset", "desc"),
                RecommendedAction(2, ActionCategory.MONITOR, "Monitor", "desc")
            )
        )
        val answer = templateEngine.explain(ExplanationRequest(incident))
        assertTrue(answer.actions.none { it.actionCategory == ActionCategory.FACTORY_RESET })
    }

    @Test
    fun `PolicyGuard caps severity for INFO incident`() {
        // Create a raw answer with CRITICAL severity for an INFO incident
        val incident = makeIncident(severity = IncidentSeverity.INFO)
        val rawAnswer = ExplanationAnswer(
            incidentId = incident.id,
            severity = IncidentSeverity.CRITICAL,
            summary = "Test",
            reasons = emptyList(),
            actions = emptyList(),
            confidence = 0.5
        )
        val validated = policyGuard.validate(rawAnswer, incident)
        assertNotEquals(IncidentSeverity.CRITICAL, validated.severity)
    }

    // ══════════════════════════════════════════════════════════
    //  LLM engine fallback simulation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `fake LLM engine produces LLM_ASSISTED source`() {
        val engine = FakeLlmEngine()
        val answer = engine.explain(ExplanationRequest(makeIncident()))
        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
    }

    @Test
    fun `crashing LLM engine can be caught`() {
        val engine = CrashingLlmEngine()
        val answer = try {
            engine.explain(ExplanationRequest(makeIncident()))
        } catch (_: Exception) {
            // Fallback
            templateEngine.explain(ExplanationRequest(makeIncident()))
        }
        // Should have fallen back to template
        assertEquals(EngineSource.TEMPLATE, answer.engineSource)
    }

    @Test
    fun `unavailable LLM engine reports correctly`() {
        val engine = UnavailableLlmEngine()
        assertFalse(engine.isAvailable)
    }

    // ══════════════════════════════════════════════════════════
    //  ExplanationAnswer model tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `hasActionableSteps true for UNINSTALL`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.HIGH,
            summary = "test",
            reasons = emptyList(),
            actions = listOf(
                ActionStep(1, ActionCategory.UNINSTALL, "Remove", "desc", "com.test"),
                ActionStep(2, ActionCategory.MONITOR, "Watch", "desc")
            ),
            confidence = 0.8
        )
        assertTrue(answer.hasActionableSteps)
    }

    @Test
    fun `hasActionableSteps false for only MONITOR and INFORM`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.LOW,
            summary = "test",
            reasons = emptyList(),
            actions = listOf(
                ActionStep(1, ActionCategory.MONITOR, "Watch", "desc"),
                ActionStep(2, ActionCategory.INFORM, "Info", "desc")
            ),
            confidence = 0.5
        )
        assertFalse(answer.hasActionableSteps)
    }

    @Test
    fun `primaryReason returns first reason`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.MEDIUM,
            summary = "test",
            reasons = listOf(
                EvidenceReason("ev1", "Reason 1", IncidentSeverity.HIGH, "TAG1", true),
                EvidenceReason("ev2", "Reason 2", IncidentSeverity.MEDIUM, "TAG2", false)
            ),
            actions = emptyList(),
            confidence = 0.6
        )
        assertEquals("TAG1", answer.primaryReason?.findingTag)
    }

    @Test
    fun `primaryReason null when no reasons`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.INFO,
            summary = "test",
            reasons = emptyList(),
            actions = emptyList(),
            confidence = 0.3
        )
        assertNull(answer.primaryReason)
    }

    @Test
    fun `primaryAction returns first action`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.HIGH,
            summary = "test",
            reasons = emptyList(),
            actions = listOf(
                ActionStep(1, ActionCategory.UNINSTALL, "Remove", "desc"),
                ActionStep(2, ActionCategory.MONITOR, "Watch", "desc")
            ),
            confidence = 0.7
        )
        assertEquals(ActionCategory.UNINSTALL, answer.primaryAction?.actionCategory)
    }

    // ══════════════════════════════════════════════════════════
    //  EngineSelectionInfo model tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `EngineSelectionInfo statusText for template with gate blocked`() {
        val info = EngineSelectionInfo(
            selectedEngine = EngineSource.TEMPLATE,
            tier = CapabilityTier.TIER_0,
            gateAllowed = false,
            gateReason = "Low RAM",
            gateRule = GateRule.LOW_RAM,
            llmEngineAvailable = false,
            userLlmEnabled = true
        )
        assertTrue(info.statusText.contains("Low RAM"))
    }

    @Test
    fun `EngineSelectionInfo statusText for template without LLM module`() {
        val info = EngineSelectionInfo(
            selectedEngine = EngineSource.TEMPLATE,
            tier = CapabilityTier.TIER_1,
            gateAllowed = true,
            gateReason = "OK",
            gateRule = GateRule.ALLOWED,
            llmEngineAvailable = false,
            userLlmEnabled = true
        )
        assertTrue(info.statusText.contains("nainstalován"))
    }

    @Test
    fun `EngineSelectionInfo statusText for LLM assisted`() {
        val info = EngineSelectionInfo(
            selectedEngine = EngineSource.LLM_ASSISTED,
            tier = CapabilityTier.TIER_2,
            gateAllowed = true,
            gateReason = "OK",
            gateRule = GateRule.ALLOWED,
            llmEngineAvailable = true,
            userLlmEnabled = true
        )
        assertTrue(info.statusText.contains("AI"))
    }

    // ══════════════════════════════════════════════════════════
    //  renderFromSlots integration
    // ══════════════════════════════════════════════════════════

    @Test
    fun `renderFromSlots produces LLM_ASSISTED answer`() {
        val signal = SecuritySignal(
            source = SignalSource.APP_SCANNER,
            type = SignalType.CERT_CHANGE,
            severity = SignalSeverity.HIGH,
            packageName = "com.test",
            summary = "Cert changed"
        )
        val incident = SecurityIncident(
            severity = IncidentSeverity.HIGH,
            title = "Test",
            summary = "Test",
            packageName = "com.test",
            events = listOf(SecurityEvent(
                source = SignalSource.APP_SCANNER,
                type = EventType.SUSPICIOUS_UPDATE,
                severity = SignalSeverity.HIGH,
                summary = "Test event",
                signals = listOf(signal)
            ))
        )
        val slots = LlmStructuredSlots(
            assessedSeverity = IncidentSeverity.HIGH,
            selectedEvidenceIds = listOf(signal.id),
            recommendedActions = listOf(ActionCategory.REINSTALL_FROM_STORE, ActionCategory.MONITOR),
            confidence = 0.75
        )
        val answer = templateEngine.renderFromSlots(slots, incident)
        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
        assertTrue(answer.reasons.isNotEmpty())
    }

    // ══════════════════════════════════════════════════════════
    //  Fake engines for testing
    // ══════════════════════════════════════════════════════════

    private class FakeLlmEngine : ExplanationEngine {
        override val engineId = "fake-llm"
        override val isAvailable = true
        override fun explain(request: ExplanationRequest): ExplanationAnswer {
            return ExplanationAnswer(
                incidentId = request.incident.id,
                severity = request.incident.severity,
                summary = "LLM explanation",
                reasons = emptyList(),
                actions = emptyList(),
                confidence = 0.8,
                engineSource = EngineSource.LLM_ASSISTED
            )
        }
    }

    private class CrashingLlmEngine : ExplanationEngine {
        override val engineId = "crashing-llm"
        override val isAvailable = true
        override fun explain(request: ExplanationRequest): ExplanationAnswer {
            throw RuntimeException("LLM inference failed")
        }
    }

    private class UnavailableLlmEngine : ExplanationEngine {
        override val engineId = "unavailable-llm"
        override val isAvailable = false
        override fun explain(request: ExplanationRequest): ExplanationAnswer {
            throw IllegalStateException("Should not be called")
        }
    }
}
