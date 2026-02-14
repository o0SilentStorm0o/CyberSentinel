package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for TemplateExplanationEngine — deterministic Czech template engine.
 *
 * Tests verify:
 *  1. Summary generation from event types
 *  2. Reason building from hypotheses and signals
 *  3. Action step generation with policy filtering
 *  4. WhenToIgnore guidance by severity
 *  5. PolicyGuard integration (post-validation)
 *  6. LLM slot rendering (renderFromSlots)
 */
class TemplateExplanationEngineTest {

    private lateinit var policyGuard: PolicyGuard
    private lateinit var engine: TemplateExplanationEngine

    @Before
    fun setUp() {
        policyGuard = PolicyGuard()
        engine = TemplateExplanationEngine(policyGuard)
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeSignal(
        type: SignalType,
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.app"
    ) = SecuritySignal(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Signal: ${type.name}"
    )

    private fun makeEvent(
        type: EventType,
        signals: List<SecuritySignal>,
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.app"
    ) = SecurityEvent(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Event: ${type.name}",
        signals = signals
    )

    private fun makeHypothesis(
        name: String,
        confidence: Double,
        evidence: List<String> = listOf("ev1")
    ) = Hypothesis(
        name = name,
        description = "Hypothesis: $name",
        confidence = confidence,
        supportingEvidence = evidence
    )

    private fun makeIncident(
        severity: IncidentSeverity,
        events: List<SecurityEvent>,
        hypotheses: List<Hypothesis> = emptyList(),
        actions: List<RecommendedAction> = emptyList(),
        pkg: String? = "com.test.app"
    ) = SecurityIncident(
        severity = severity,
        title = "Test",
        summary = "Test incident",
        packageName = pkg,
        events = events,
        hypotheses = hypotheses,
        recommendedActions = actions
    )

    // ══════════════════════════════════════════════════════════
    //  Engine metadata
    // ══════════════════════════════════════════════════════════

    @Test
    fun `engine has correct ID`() {
        assertEquals("template-v1", engine.engineId)
    }

    @Test
    fun `engine is always available`() {
        assertTrue(engine.isAvailable)
    }

    // ══════════════════════════════════════════════════════════
    //  Summary generation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `summary uses event type template`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE)
                ))
            ),
            hypotheses = listOf(makeHypothesis("suspicious_update", 0.5))
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue("Summary should mention the package",
            answer.summary.contains("com.test.app"))
    }

    @Test
    fun `critical severity gets emoji prefix`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.COMBO_DETECTED, SignalSeverity.CRITICAL),
                    makeSignal(SignalType.SPECIAL_ACCESS_ENABLED, SignalSeverity.HIGH),
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("confirmed_stalkerware", 0.9))
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue("Critical summary should have emoji", answer.summary.contains("🔴"))
    }

    @Test
    fun `stalkerware event uses correct Czech template`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.COMBO_DETECTED)
                ))
            ),
            hypotheses = listOf(makeHypothesis("possible_stalkerware", 0.6))
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue(answer.summary.contains("sledovacího"))
    }

    // ══════════════════════════════════════════════════════════
    //  Reason building
    // ══════════════════════════════════════════════════════════

    @Test
    fun `reasons built from hypotheses`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE)
                ))
            ),
            hypotheses = listOf(
                makeHypothesis("supply_chain_compromise", 0.7),
                makeHypothesis("suspicious_update", 0.5)
            )
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue("Should have reasons from hypotheses", answer.reasons.isNotEmpty())
        // Higher confidence hypothesis should come first (after sorting by HARD then severity)
        val tags = answer.reasons.map { it.findingTag }
        assertTrue(tags.contains("supply_chain_compromise"))
        assertTrue(tags.contains("suspicious_update"))
    }

    @Test
    fun `reasons include signal-based entries for uncovered signal types`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE),
                    makeSignal(SignalType.VERSION_ROLLBACK)
                ))
            ),
            hypotheses = emptyList() // no hypotheses → all reasons from signals
        )
        val answer = engine.explain(ExplanationRequest(incident))
        val tags = answer.reasons.map { it.findingTag }
        assertTrue(tags.contains("CERT_CHANGE"))
        assertTrue(tags.contains("VERSION_ROLLBACK"))
    }

    @Test
    fun `hard evidence reasons sorted first`() {
        val certSignal = makeSignal(SignalType.CERT_CHANGE, SignalSeverity.HIGH) // → HARD
        val nativeSignal = makeSignal(SignalType.SUSPICIOUS_NATIVE_LIB, SignalSeverity.MEDIUM) // → WEAK
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(nativeSignal, certSignal))
            )
        )
        val answer = engine.explain(ExplanationRequest(incident))
        if (answer.reasons.size >= 2) {
            assertTrue("HARD evidence should be sorted first",
                answer.reasons[0].isHardEvidence || !answer.reasons[1].isHardEvidence)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Action step generation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `actions generated from recommended actions`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_INSTALL, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("malicious_update", 0.8)),
            actions = listOf(
                RecommendedAction(1, ActionCategory.UNINSTALL, "Odinstalovat", "desc", "com.test.app"),
                RecommendedAction(2, ActionCategory.MONITOR, "Sledovat", "desc", "com.test.app")
            )
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertEquals(2, answer.actions.size)
        assertEquals(ActionCategory.UNINSTALL, answer.actions[0].actionCategory)
        assertEquals(1, answer.actions[0].stepNumber)
        assertTrue(answer.actions[0].isUrgent) // UNINSTALL is urgent
        assertFalse(answer.actions[1].isUrgent) // MONITOR is not urgent
    }

    @Test
    fun `factory reset filtered out by PolicyGuard for non-critical`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH, // not CRITICAL
            events = listOf(
                makeEvent(EventType.DEVICE_COMPROMISE, listOf(
                    makeSignal(SignalType.CERT_CHANGE)
                ))
            ),
            actions = listOf(
                RecommendedAction(1, ActionCategory.UNINSTALL, "Odinstalovat", "desc"),
                RecommendedAction(2, ActionCategory.FACTORY_RESET, "Reset", "desc"),
                RecommendedAction(3, ActionCategory.MONITOR, "Sledovat", "desc")
            )
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue("Factory reset should be filtered",
            answer.actions.none { it.actionCategory == ActionCategory.FACTORY_RESET })
    }

    // ══════════════════════════════════════════════════════════
    //  WhenToIgnore guidance
    // ══════════════════════════════════════════════════════════

    @Test
    fun `whenToIgnore present for INFO severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.INFO,
            events = emptyList()
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertNotNull(answer.whenToIgnore)
        assertTrue(answer.whenToIgnore!!.contains("informační"))
    }

    @Test
    fun `whenToIgnore present for LOW severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.LOW,
            events = emptyList()
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertNotNull(answer.whenToIgnore)
    }

    @Test
    fun `whenToIgnore present for MEDIUM severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = emptyList()
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertNotNull(answer.whenToIgnore)
    }

    @Test
    fun `whenToIgnore null for HIGH severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_INSTALL, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("malicious_update", 0.8))
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertNull(answer.whenToIgnore)
    }

    @Test
    fun `whenToIgnore null for CRITICAL severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.DEVICE_COMPROMISE, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("device_rooted", 0.9))
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertNull(answer.whenToIgnore)
    }

    // ══════════════════════════════════════════════════════════
    //  PolicyGuard integration
    // ══════════════════════════════════════════════════════════

    @Test
    fun `answer always has SafeLanguageFlags attached`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = emptyList()
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue("Should have NO_VIRUS_CLAIM at minimum",
            SafeLanguageFlag.NO_VIRUS_CLAIM in answer.safeLanguageFlags)
    }

    @Test
    fun `engine source is TEMPLATE`() {
        val incident = makeIncident(
            severity = IncidentSeverity.LOW,
            events = emptyList()
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertEquals(EngineSource.TEMPLATE, answer.engineSource)
    }

    // ══════════════════════════════════════════════════════════
    //  ExplanationAnswer helpers
    // ══════════════════════════════════════════════════════════

    @Test
    fun `hasActionableSteps true when UNINSTALL present`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.HIGH,
            summary = "test",
            reasons = emptyList(),
            actions = listOf(
                ActionStep(1, ActionCategory.UNINSTALL, "Odinstalovat", "desc", "com.test"),
                ActionStep(2, ActionCategory.MONITOR, "Sledovat", "desc")
            ),
            confidence = 0.8
        )
        assertTrue(answer.hasActionableSteps)
    }

    @Test
    fun `hasActionableSteps false when only MONITOR and INFORM`() {
        val answer = ExplanationAnswer(
            incidentId = "test",
            severity = IncidentSeverity.LOW,
            summary = "test",
            reasons = emptyList(),
            actions = listOf(
                ActionStep(1, ActionCategory.MONITOR, "Sledovat", "desc"),
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

    // ══════════════════════════════════════════════════════════
    //  renderFromSlots (for future LLM integration)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `renderFromSlots produces valid answer`() {
        val signal = makeSignal(SignalType.CERT_CHANGE, SignalSeverity.HIGH)
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(signal))
            )
        )
        val slots = LlmStructuredSlots(
            assessedSeverity = IncidentSeverity.HIGH,
            selectedEvidenceIds = listOf(signal.id),
            recommendedActions = listOf(ActionCategory.REINSTALL_FROM_STORE, ActionCategory.MONITOR),
            confidence = 0.75
        )
        val answer = engine.renderFromSlots(slots, incident)
        assertEquals(EngineSource.LLM_ASSISTED, answer.engineSource)
        assertTrue(answer.reasons.isNotEmpty())
        assertTrue(answer.actions.isNotEmpty())
    }

    @Test
    fun `renderFromSlots filters factory reset via PolicyGuard`() {
        val signal = makeSignal(SignalType.SUSPICIOUS_NATIVE_LIB) // WEAK
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_INSTALL, listOf(signal))
            )
        )
        val slots = LlmStructuredSlots(
            assessedSeverity = IncidentSeverity.MEDIUM,
            selectedEvidenceIds = listOf(signal.id),
            recommendedActions = listOf(ActionCategory.FACTORY_RESET, ActionCategory.MONITOR),
            confidence = 0.5
        )
        val answer = engine.renderFromSlots(slots, incident)
        assertTrue("Factory reset should be filtered for MEDIUM severity",
            answer.actions.none { it.actionCategory == ActionCategory.FACTORY_RESET })
    }

    // ══════════════════════════════════════════════════════════
    //  Template coverage
    // ══════════════════════════════════════════════════════════

    @Test
    fun `all EventTypes have summary templates`() {
        for (eventType in EventType.values()) {
            assertTrue(
                "Missing summary template for $eventType",
                TemplateExplanationEngine.summaryTemplates.containsKey(eventType)
            )
        }
    }

    @Test
    fun `all ActionCategories have title templates`() {
        for (category in ActionCategory.values()) {
            assertTrue(
                "Missing action title template for $category",
                TemplateExplanationEngine.actionTitleTemplates.containsKey(category)
            )
        }
    }

    @Test
    fun `all ActionCategories have description templates`() {
        for (category in ActionCategory.values()) {
            assertTrue(
                "Missing action description template for $category",
                TemplateExplanationEngine.actionDescriptionTemplates.containsKey(category)
            )
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Config event handling
    // ══════════════════════════════════════════════════════════

    @Test
    fun `CA cert installed event generates proper explanation`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.CA_CERT_INSTALLED, listOf(
                    makeSignal(SignalType.USER_CA_CERT_ADDED, SignalSeverity.HIGH)
                ))
            ),
            hypotheses = listOf(makeHypothesis("mitm_attack", 0.6)),
            actions = listOf(
                RecommendedAction(1, ActionCategory.CHECK_SETTINGS, "Zkontrolovat", "desc")
            )
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue(answer.summary.contains("certifikát"))
        assertTrue(answer.actions.isNotEmpty())
    }

    @Test
    fun `config tamper event generates proper explanation`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.CONFIG_TAMPER, listOf(
                    makeSignal(SignalType.PRIVATE_DNS_CHANGED, SignalSeverity.MEDIUM)
                ))
            ),
            hypotheses = listOf(makeHypothesis("config_tampering", 0.5)),
            pkg = null // config events have no package
        )
        val answer = engine.explain(ExplanationRequest(incident))
        assertTrue(answer.summary.contains("nastavení"))
    }
}
