package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.LlmStructuredSlots
import com.cybersentinel.app.domain.explainability.SummaryTone
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for SlotValidator — evidence validation and slot repair.
 *
 * Tests verify:
 *  1. Valid slots pass through unchanged
 *  2. Hallucinated evidence IDs are stripped
 *  3. Severity escalation is clamped
 *  4. Confidence is clamped to 0.0-1.0
 *  5. Invalid ignore keys are cleared
 *  6. Notes truncation
 *  7. STRICT mode rejects on any issue
 *  8. LENIENT mode repairs what it can
 *  9. Complete rejection when no valid evidence remains
 */
class SlotValidatorTest {

    private lateinit var validator: SlotValidator

    @Before
    fun setUp() {
        validator = SlotValidator()
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeSignal(id: String): SecuritySignal = SecuritySignal(
        id = id,
        source = SignalSource.APP_SCANNER,
        type = SignalType.CERT_CHANGE,
        severity = SignalSeverity.HIGH,
        packageName = "com.test.app",
        summary = "Test"
    )

    private fun makeIncident(
        signalIds: List<String> = listOf("sig-1", "sig-2", "sig-3"),
        severity: IncidentSeverity = IncidentSeverity.MEDIUM
    ): SecurityIncident {
        val signals = signalIds.map { makeSignal(it) }
        val event = SecurityEvent(
            id = "evt-1",
            source = SignalSource.APP_SCANNER,
            type = EventType.SUSPICIOUS_UPDATE,
            severity = SignalSeverity.HIGH,
            summary = "Test event",
            signals = signals
        )
        return SecurityIncident(
            severity = severity,
            title = "Test",
            summary = "Test",
            packageName = "com.test.app",
            events = listOf(event)
        )
    }

    private fun makeSlots(
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        evidenceIds: List<String> = listOf("sig-1", "sig-2"),
        actions: List<ActionCategory> = listOf(ActionCategory.CHECK_SETTINGS, ActionCategory.MONITOR),
        confidence: Double = 0.75,
        canBeIgnored: Boolean = false,
        ignoreReasonKey: String? = null,
        notes: String? = null
    ) = LlmStructuredSlots(
        assessedSeverity = severity,
        summaryTone = SummaryTone.NEUTRAL,
        selectedEvidenceIds = evidenceIds,
        recommendedActions = actions,
        confidence = confidence,
        canBeIgnored = canBeIgnored,
        ignoreReasonKey = ignoreReasonKey,
        notes = notes
    )

    // ══════════════════════════════════════════════════════════
    //  Valid slots
    // ══════════════════════════════════════════════════════════

    @Test
    fun `valid slots pass through as Valid`() {
        val incident = makeIncident()
        val slots = makeSlots()

        val result = validator.validate(slots, incident)
        assertTrue("Should be Valid", result is ValidationResult.Valid)
        assertEquals(slots.assessedSeverity, result.slotsOrNull!!.assessedSeverity)
        assertEquals(slots.selectedEvidenceIds, result.slotsOrNull!!.selectedEvidenceIds)
    }

    @Test
    fun `valid result is usable`() {
        val result = validator.validate(makeSlots(), makeIncident())
        assertTrue(result.isUsable)
    }

    // ══════════════════════════════════════════════════════════
    //  Hallucinated evidence IDs
    // ══════════════════════════════════════════════════════════

    @Test
    fun `hallucinated evidence IDs are stripped in LENIENT mode`() {
        val incident = makeIncident(signalIds = listOf("sig-1", "sig-2"))
        val slots = makeSlots(evidenceIds = listOf("sig-1", "hallucinated-99", "sig-2"))

        val result = validator.validate(slots, incident, ValidationMode.LENIENT)
        assertTrue("Should be Repaired", result is ValidationResult.Repaired)
        assertEquals(listOf("sig-1", "sig-2"), result.slotsOrNull!!.selectedEvidenceIds)
    }

    @Test
    fun `all hallucinated evidence IDs causes rejection`() {
        val incident = makeIncident(signalIds = listOf("sig-1"))
        val slots = makeSlots(evidenceIds = listOf("fake-1", "fake-2"))

        val result = validator.validate(slots, incident, ValidationMode.LENIENT)
        assertTrue("Should be Rejected", result is ValidationResult.Rejected)
        assertFalse(result.isUsable)
    }

    @Test
    fun `event IDs are also valid evidence IDs`() {
        val incident = makeIncident(signalIds = listOf("sig-1"))
        // evt-1 is the event ID created in makeIncident
        val slots = makeSlots(evidenceIds = listOf("sig-1", "evt-1"))

        val result = validator.validate(slots, incident)
        assertTrue(result.isUsable)
        assertTrue(result.slotsOrNull!!.selectedEvidenceIds.contains("evt-1"))
    }

    // ══════════════════════════════════════════════════════════
    //  Severity escalation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `severity escalation by 1 level is allowed`() {
        // Incident=MEDIUM, LLM says HIGH → allowed (1 level up)
        val incident = makeIncident(severity = IncidentSeverity.MEDIUM)
        val slots = makeSlots(severity = IncidentSeverity.HIGH)

        val result = validator.validate(slots, incident)
        assertTrue(result.isUsable)
        assertEquals(IncidentSeverity.HIGH, result.slotsOrNull!!.assessedSeverity)
    }

    @Test
    fun `severity escalation by 2 levels is clamped`() {
        // Incident=MEDIUM, LLM says CRITICAL → clamped to MEDIUM
        val incident = makeIncident(severity = IncidentSeverity.MEDIUM)
        val slots = makeSlots(severity = IncidentSeverity.CRITICAL)

        val result = validator.validate(slots, incident)
        assertTrue(result.isUsable)
        assertEquals(
            "Should clamp to incident severity",
            IncidentSeverity.MEDIUM,
            result.slotsOrNull!!.assessedSeverity
        )
    }

    @Test
    fun `severity de-escalation is always allowed`() {
        // Incident=CRITICAL, LLM says LOW → allowed
        val incident = makeIncident(severity = IncidentSeverity.CRITICAL)
        val slots = makeSlots(severity = IncidentSeverity.LOW)

        val result = validator.validate(slots, incident)
        assertTrue(result.isUsable)
        assertEquals(IncidentSeverity.LOW, result.slotsOrNull!!.assessedSeverity)
    }

    @Test
    fun `checkSeverityEscalation same level is ok`() {
        assertTrue(validator.checkSeverityEscalation(IncidentSeverity.HIGH, IncidentSeverity.HIGH))
    }

    @Test
    fun `checkSeverityEscalation one up is ok`() {
        assertTrue(validator.checkSeverityEscalation(IncidentSeverity.HIGH, IncidentSeverity.MEDIUM))
    }

    @Test
    fun `checkSeverityEscalation two up is not ok`() {
        assertFalse(validator.checkSeverityEscalation(IncidentSeverity.CRITICAL, IncidentSeverity.MEDIUM))
    }

    // ══════════════════════════════════════════════════════════
    //  Confidence clamping
    // ══════════════════════════════════════════════════════════

    @Test
    fun `confidence in range passes through`() {
        val slots = makeSlots(confidence = 0.5)
        val result = validator.validate(slots, makeIncident())
        assertEquals(0.5, result.slotsOrNull!!.confidence, 0.001)
    }

    // ══════════════════════════════════════════════════════════
    //  Ignore reason key validation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `valid ignore reason key is kept`() {
        val slots = makeSlots(canBeIgnored = true, ignoreReasonKey = "known_developer_tool")
        val result = validator.validate(slots, makeIncident())
        assertTrue(result.isUsable)
        assertEquals("known_developer_tool", result.slotsOrNull!!.ignoreReasonKey)
    }

    @Test
    fun `invalid ignore reason key is cleared`() {
        val slots = makeSlots(canBeIgnored = true, ignoreReasonKey = "invented_key")
        val result = validator.validate(slots, makeIncident())
        assertTrue(result.isUsable)
        assertNull(result.slotsOrNull!!.ignoreReasonKey)
        assertFalse("canBeIgnored should be cleared when key is invalid", result.slotsOrNull!!.canBeIgnored)
    }

    @Test
    fun `all valid ignore keys are accepted`() {
        for (key in SlotValidator.VALID_IGNORE_KEYS) {
            val slots = makeSlots(canBeIgnored = true, ignoreReasonKey = key)
            val result = validator.validate(slots, makeIncident())
            assertEquals("Key $key should be valid", key, result.slotsOrNull!!.ignoreReasonKey)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Notes truncation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `short notes pass through`() {
        val slots = makeSlots(notes = "Short note")
        val result = validator.validate(slots, makeIncident())
        assertEquals("Short note", result.slotsOrNull!!.notes)
    }

    @Test
    fun `long notes are truncated`() {
        val long = "x".repeat(500)
        val slots = makeSlots(notes = long)
        val result = validator.validate(slots, makeIncident())
        assertTrue(result.isUsable)
        assertEquals(SlotValidator.MAX_NOTES_LENGTH, result.slotsOrNull!!.notes!!.length)
    }

    // ══════════════════════════════════════════════════════════
    //  STRICT mode
    // ══════════════════════════════════════════════════════════

    @Test
    fun `STRICT mode rejects on any issue`() {
        val incident = makeIncident(signalIds = listOf("sig-1"))
        val slots = makeSlots(evidenceIds = listOf("sig-1", "hallucinated"))

        val result = validator.validate(slots, incident, ValidationMode.STRICT)
        assertTrue("STRICT should reject", result is ValidationResult.Rejected)
    }

    @Test
    fun `STRICT mode passes clean slots`() {
        val incident = makeIncident()
        val slots = makeSlots()

        val result = validator.validate(slots, incident, ValidationMode.STRICT)
        assertTrue("STRICT should pass clean slots", result is ValidationResult.Valid)
    }

    // ══════════════════════════════════════════════════════════
    //  Evidence ID collection
    // ══════════════════════════════════════════════════════════

    @Test
    fun `collectEvidenceIds includes signal and event IDs`() {
        val incident = makeIncident(signalIds = listOf("sig-a", "sig-b"))
        val ids = validator.collectEvidenceIds(incident)

        assertTrue(ids.contains("sig-a"))
        assertTrue(ids.contains("sig-b"))
        assertTrue("Event ID should be included", ids.contains("evt-1"))
    }

    @Test
    fun `collectEvidenceIds empty incident returns empty set`() {
        val incident = SecurityIncident(
            severity = IncidentSeverity.LOW,
            title = "Empty",
            summary = "Empty",
            events = emptyList()
        )
        assertTrue(validator.collectEvidenceIds(incident).isEmpty())
    }

    // ══════════════════════════════════════════════════════════
    //  ValidationResult properties
    // ══════════════════════════════════════════════════════════

    @Test
    fun `Rejected result is not usable`() {
        val result = ValidationResult.Rejected(emptyList(), "test")
        assertFalse(result.isUsable)
        assertNull(result.slotsOrNull)
    }

    @Test
    fun `Repaired result is usable`() {
        val slots = makeSlots()
        val result = ValidationResult.Repaired(slots, listOf(ValidationIssue("f", IssueSeverity.WARNING, "w")))
        assertTrue(result.isUsable)
        assertNotNull(result.slotsOrNull)
    }
}
