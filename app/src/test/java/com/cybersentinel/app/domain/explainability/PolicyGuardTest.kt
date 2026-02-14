package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for PolicyGuard — evidence-based policy constraint engine.
 *
 * Tests verify:
 *  1. Constraint determination based on evidence analysis
 *  2. Post-validation corrections (action removal, severity capping)
 *  3. Edge cases (empty incidents, no hypotheses, mixed evidence)
 */
class PolicyGuardTest {

    private lateinit var policyGuard: PolicyGuard

    @Before
    fun setUp() {
        policyGuard = PolicyGuard()
    }

    // ══════════════════════════════════════════════════════════
    //  Helper builders
    // ══════════════════════════════════════════════════════════

    private fun makeSignal(
        type: SignalType,
        severity: SignalSeverity = SignalSeverity.HIGH,
        packageName: String? = "com.test.app"
    ) = SecuritySignal(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = packageName,
        summary = "Test signal: ${type.name}"
    )

    private fun makeEvent(
        type: EventType,
        signals: List<SecuritySignal>,
        severity: SignalSeverity = SignalSeverity.HIGH,
        packageName: String? = "com.test.app"
    ) = SecurityEvent(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = packageName,
        summary = "Test event: ${type.name}",
        signals = signals
    )

    private fun makeIncident(
        severity: IncidentSeverity,
        events: List<SecurityEvent>,
        hypotheses: List<Hypothesis> = emptyList(),
        actions: List<RecommendedAction> = emptyList(),
        packageName: String? = "com.test.app"
    ) = SecurityIncident(
        severity = severity,
        title = "Test incident",
        summary = "Test",
        packageName = packageName,
        events = events,
        hypotheses = hypotheses,
        recommendedActions = actions
    )

    private fun makeHypothesis(
        name: String,
        confidence: Double,
        evidence: List<String> = listOf("ev1")
    ) = Hypothesis(
        name = name,
        description = "Test hypothesis",
        confidence = confidence,
        supportingEvidence = evidence
    )

    private fun makeAnswer(
        severity: IncidentSeverity = IncidentSeverity.HIGH,
        actions: List<ActionStep> = emptyList()
    ) = ExplanationAnswer(
        incidentId = "test-incident",
        severity = severity,
        summary = "Test summary",
        reasons = emptyList(),
        actions = actions,
        confidence = 0.7
    )

    // ══════════════════════════════════════════════════════════
    //  NO_VIRUS_CLAIM — always active
    // ══════════════════════════════════════════════════════════

    @Test
    fun `virus claim always blocked`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL),
                    makeSignal(SignalType.COMBO_DETECTED, SignalSeverity.HIGH),
                    makeSignal(SignalType.SPECIAL_ACCESS_ENABLED, SignalSeverity.HIGH)
                ))
            ),
            hypotheses = listOf(makeHypothesis("confirmed_stalkerware", 0.95))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue("NO_VIRUS_CLAIM should always be active",
            SafeLanguageFlag.NO_VIRUS_CLAIM in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  NO_MALWARE_CLAIM — requires HARD evidence + confidence
    // ══════════════════════════════════════════════════════════

    @Test
    fun `malware claim blocked without hard evidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_INSTALL, listOf(
                    makeSignal(SignalType.SUSPICIOUS_NATIVE_LIB) // WEAK_SIGNAL, not HARD
                ))
            ),
            hypotheses = listOf(makeHypothesis("generic_risk", 0.8))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue("NO_MALWARE_CLAIM should be active without HARD evidence",
            SafeLanguageFlag.NO_MALWARE_CLAIM in constraints)
    }

    @Test
    fun `malware claim allowed with hard evidence and high confidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE, SignalSeverity.CRITICAL), // → SIGNATURE_MISMATCH = HARD
                    makeSignal(SignalType.HIGH_RISK_PERM_ADDED, SignalSeverity.HIGH) // HARD
                ))
            ),
            hypotheses = listOf(makeHypothesis("supply_chain_compromise", 0.85))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertFalse("NO_MALWARE_CLAIM should NOT be active with HARD evidence + high confidence",
            SafeLanguageFlag.NO_MALWARE_CLAIM in constraints)
    }

    @Test
    fun `malware claim blocked with hard evidence but low confidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE, SignalSeverity.HIGH) // HARD
                ))
            ),
            hypotheses = listOf(makeHypothesis("suspicious_update", 0.4)) // below threshold
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue("NO_MALWARE_CLAIM should be active with low confidence",
            SafeLanguageFlag.NO_MALWARE_CLAIM in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  NO_COMPROMISE_CLAIM — stricter threshold
    // ══════════════════════════════════════════════════════════

    @Test
    fun `compromise claim blocked below 0_7 confidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL) // HARD
                ))
            ),
            hypotheses = listOf(makeHypothesis("malicious_update", 0.65)) // above malware, below compromise
        )
        val constraints = policyGuard.determineConstraints(incident)
        // Malware claim allowed (>0.6 + HARD)
        assertFalse(SafeLanguageFlag.NO_MALWARE_CLAIM in constraints)
        // Compromise claim blocked (<0.7)
        assertTrue(SafeLanguageFlag.NO_COMPROMISE_CLAIM in constraints)
    }

    @Test
    fun `compromise claim allowed at 0_7 confidence with hard evidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("confirmed_stalkerware", 0.75))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertFalse(SafeLanguageFlag.NO_COMPROMISE_CLAIM in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  NO_FACTORY_RESET — requires CRITICAL + HARD
    // ══════════════════════════════════════════════════════════

    @Test
    fun `factory reset blocked for non-critical incident`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("malicious_update", 0.9))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue(SafeLanguageFlag.NO_FACTORY_RESET in constraints)
    }

    @Test
    fun `factory reset allowed for critical with hard evidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.DEVICE_COMPROMISE, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("device_rooted", 0.9))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertFalse(SafeLanguageFlag.NO_FACTORY_RESET in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  NO_SPYING_CLAIM — requires confirmed stalkerware
    // ══════════════════════════════════════════════════════════

    @Test
    fun `spying claim blocked without confirmed stalkerware`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.COMBO_DETECTED) // no SPECIAL_ACCESS_ENABLED
                ))
            ),
            hypotheses = listOf(makeHypothesis("possible_stalkerware", 0.6))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue(SafeLanguageFlag.NO_SPYING_CLAIM in constraints)
    }

    @Test
    fun `spying claim allowed with combo + special access + hard evidence`() {
        val incident = makeIncident(
            severity = IncidentSeverity.CRITICAL,
            events = listOf(
                makeEvent(EventType.STALKERWARE_PATTERN, listOf(
                    makeSignal(SignalType.COMBO_DETECTED, SignalSeverity.HIGH),
                    makeSignal(SignalType.SPECIAL_ACCESS_ENABLED, SignalSeverity.HIGH),
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL) // HARD
                ))
            ),
            hypotheses = listOf(makeHypothesis("confirmed_stalkerware", 0.9))
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertFalse(SafeLanguageFlag.NO_SPYING_CLAIM in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  NO_ALARMIST_FRAMING — INFO/LOW severity only
    // ══════════════════════════════════════════════════════════

    @Test
    fun `alarmist framing blocked for INFO severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.INFO,
            events = emptyList()
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue(SafeLanguageFlag.NO_ALARMIST_FRAMING in constraints)
    }

    @Test
    fun `alarmist framing blocked for LOW severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.LOW,
            events = emptyList()
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertTrue(SafeLanguageFlag.NO_ALARMIST_FRAMING in constraints)
    }

    @Test
    fun `alarmist framing allowed for MEDIUM severity`() {
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM,
            events = emptyList()
        )
        val constraints = policyGuard.determineConstraints(incident)
        assertFalse(SafeLanguageFlag.NO_ALARMIST_FRAMING in constraints)
    }

    // ══════════════════════════════════════════════════════════
    //  Post-validation: factory reset removal
    // ══════════════════════════════════════════════════════════

    @Test
    fun `validate removes factory reset when constraint active`() {
        val answer = makeAnswer(
            severity = IncidentSeverity.HIGH,
            actions = listOf(
                ActionStep(1, ActionCategory.UNINSTALL, "Odinstalovat", "desc", "com.test"),
                ActionStep(2, ActionCategory.FACTORY_RESET, "Reset", "desc"),
                ActionStep(3, ActionCategory.MONITOR, "Sledovat", "desc")
            )
        )
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH, // not CRITICAL → NO_FACTORY_RESET active
            events = emptyList()
        )
        val validated = policyGuard.validate(answer, incident)
        assertTrue(validated.actions.none { it.actionCategory == ActionCategory.FACTORY_RESET })
        assertEquals(2, validated.actions.size)
        // Steps should be renumbered
        assertEquals(1, validated.actions[0].stepNumber)
        assertEquals(2, validated.actions[1].stepNumber)
        assertTrue(validated.policyViolationsFound > 0)
    }

    // ══════════════════════════════════════════════════════════
    //  Post-validation: severity capping
    // ══════════════════════════════════════════════════════════

    @Test
    fun `validate caps severity for alarmist INFO incident`() {
        val answer = makeAnswer(severity = IncidentSeverity.CRITICAL)
        val incident = makeIncident(
            severity = IncidentSeverity.INFO,
            events = emptyList()
        )
        val validated = policyGuard.validate(answer, incident)
        assertEquals(IncidentSeverity.MEDIUM, validated.severity)
    }

    @Test
    fun `validate caps CRITICAL to HIGH when no hard evidence`() {
        val answer = makeAnswer(severity = IncidentSeverity.CRITICAL)
        val incident = makeIncident(
            severity = IncidentSeverity.MEDIUM, // not INFO/LOW so NO_ALARMIST not triggered
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_INSTALL, listOf(
                    makeSignal(SignalType.SUSPICIOUS_NATIVE_LIB) // WEAK_SIGNAL, not HARD
                ))
            )
        )
        val validated = policyGuard.validate(answer, incident)
        assertEquals(IncidentSeverity.HIGH, validated.severity)
    }

    // ══════════════════════════════════════════════════════════
    //  Edge cases
    // ══════════════════════════════════════════════════════════

    @Test
    fun `empty incident gets maximum constraints`() {
        val incident = makeIncident(
            severity = IncidentSeverity.INFO,
            events = emptyList(),
            hypotheses = emptyList()
        )
        val constraints = policyGuard.determineConstraints(incident)
        // Should have all flags except maybe NO_FACTORY_RESET (depends on severity check ordering)
        assertTrue(SafeLanguageFlag.NO_VIRUS_CLAIM in constraints)
        assertTrue(SafeLanguageFlag.NO_MALWARE_CLAIM in constraints)
        assertTrue(SafeLanguageFlag.NO_COMPROMISE_CLAIM in constraints)
        assertTrue(SafeLanguageFlag.NO_SPYING_CLAIM in constraints)
        assertTrue(SafeLanguageFlag.NO_ALARMIST_FRAMING in constraints)
    }

    @Test
    fun `extractHardFindingTypes maps signal types correctly`() {
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.CERT_CHANGE),
                    makeSignal(SignalType.VERSION_ROLLBACK),
                    makeSignal(SignalType.SUSPICIOUS_NATIVE_LIB) // WEAK_SIGNAL → not in HARD set
                ))
            )
        )
        val hardTypes = policyGuard.extractHardFindingTypes(incident)
        assertTrue(TrustRiskModel.FindingType.SIGNATURE_MISMATCH in hardTypes)
        assertTrue(TrustRiskModel.FindingType.VERSION_ROLLBACK in hardTypes)
        assertFalse(TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB in hardTypes) // WEAK_SIGNAL
    }

    @Test
    fun `isActionAllowed respects constraints`() {
        val constraints = setOf(SafeLanguageFlag.NO_FACTORY_RESET)
        assertFalse(policyGuard.isActionAllowed(ActionCategory.FACTORY_RESET, constraints))
        assertTrue(policyGuard.isActionAllowed(ActionCategory.UNINSTALL, constraints))
        assertTrue(policyGuard.isActionAllowed(ActionCategory.MONITOR, constraints))
    }

    @Test
    fun `validate preserves answer when no violations`() {
        val answer = makeAnswer(
            severity = IncidentSeverity.HIGH,
            actions = listOf(
                ActionStep(1, ActionCategory.UNINSTALL, "Odinstalovat", "desc", "com.test")
            )
        )
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            events = listOf(
                makeEvent(EventType.SUSPICIOUS_UPDATE, listOf(
                    makeSignal(SignalType.DEBUG_SIGNATURE, SignalSeverity.CRITICAL)
                ))
            ),
            hypotheses = listOf(makeHypothesis("malicious_update", 0.8))
        )
        val validated = policyGuard.validate(answer, incident)
        assertEquals(IncidentSeverity.HIGH, validated.severity)
        assertEquals(1, validated.actions.size)
        assertEquals(0, validated.policyViolationsFound)
    }
}
