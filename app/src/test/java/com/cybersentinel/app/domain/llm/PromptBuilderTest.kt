package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.SafeLanguageFlag
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for PromptBuilder — structured prompt construction.
 *
 * Tests verify:
 *  1. Prompt structure (system instruction, incident context, constraints, output instruction)
 *  2. Anonymization of package names
 *  3. Evidence IDs present in prompt (for FakeLlmRuntime to extract)
 *  4. PolicyGuard constraints embedded as prompt directives
 *  5. Token budget limits (MAX_EVENTS, MAX_SIGNALS_PER_EVENT, MAX_HYPOTHESES)
 *  6. Empty/edge cases
 */
class PromptBuilderTest {

    private lateinit var builder: PromptBuilder

    @Before
    fun setUp() {
        builder = PromptBuilder()
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeSignal(
        id: String = "sig-001",
        type: SignalType = SignalType.CERT_CHANGE,
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.app"
    ): SecuritySignal = SecuritySignal(
        id = id,
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Test signal"
    )

    private fun makeIncident(
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        signals: List<SecuritySignal> = listOf(makeSignal()),
        hypotheses: List<Hypothesis> = emptyList(),
        pkg: String = "com.test.app"
    ): SecurityIncident {
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.SUSPICIOUS_UPDATE,
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
            hypotheses = hypotheses,
            recommendedActions = listOf(
                RecommendedAction(1, ActionCategory.CHECK_SETTINGS, "Check", "desc", pkg)
            )
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Structure tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `buildPrompt contains system instruction with schema`() {
        val incident = makeIncident()
        val prompt = builder.buildPrompt(incident, emptySet())

        assertTrue("Must contain assessed_severity schema", prompt.contains("assessed_severity"))
        assertTrue("Must contain reason_ids schema", prompt.contains("reason_ids"))
        assertTrue("Must contain action_categories schema", prompt.contains("action_categories"))
        assertTrue("Must contain confidence schema", prompt.contains("confidence"))
        assertTrue("Must contain output-only instruction", prompt.contains("Respond with ONLY the JSON"))
    }

    @Test
    fun `buildPrompt contains incident context`() {
        val signal = makeSignal(id = "evidence-abc")
        val incident = makeIncident(
            severity = IncidentSeverity.HIGH,
            signals = listOf(signal)
        )
        val prompt = builder.buildPrompt(incident, emptySet())

        assertTrue("Must contain INCIDENT section", prompt.contains("INCIDENT:"))
        assertTrue("Must contain severity", prompt.contains("severity: HIGH"))
        assertTrue("Must contain evidence_id", prompt.contains("evidence_id: evidence-abc"))
        assertTrue("Must contain signal type", prompt.contains("signal: CERT_CHANGE"))
    }

    @Test
    fun `buildPrompt contains constraints`() {
        val incident = makeIncident()
        val constraints = setOf(SafeLanguageFlag.NO_VIRUS_CLAIM, SafeLanguageFlag.NO_MALWARE_CLAIM)
        val prompt = builder.buildPrompt(incident, constraints)

        assertTrue("Must contain constraints section", prompt.contains("CONSTRAINTS"))
        assertTrue("Must contain NO_VIRUS directive", prompt.contains("NEVER use the term 'virus'"))
        assertTrue("Must contain NO_MALWARE directive", prompt.contains("DO NOT claim this is malware"))
    }

    @Test
    fun `buildPrompt with empty constraints says no additional constraints`() {
        val incident = makeIncident()
        val prompt = builder.buildPrompt(incident, emptySet())

        assertTrue(prompt.contains("No additional constraints"))
    }

    // ══════════════════════════════════════════════════════════
    //  Privacy / anonymization
    // ══════════════════════════════════════════════════════════

    @Test
    fun `anonymizePackage returns package name for non-null`() {
        assertEquals("com.example.app", builder.anonymizePackage("com.example.app"))
    }

    @Test
    fun `anonymizePackage returns unknown_app for null`() {
        assertEquals("unknown_app", builder.anonymizePackage(null))
    }

    @Test
    fun `buildPrompt with null packageName uses unknown_app`() {
        val incident = makeIncident(pkg = "com.test.app").copy(packageName = null)
        val prompt = builder.buildPrompt(incident, emptySet())

        assertTrue(prompt.contains("unknown_app"))
    }

    // ══════════════════════════════════════════════════════════
    //  Token budget limits
    // ══════════════════════════════════════════════════════════

    @Test
    fun `buildIncidentContext limits events to MAX_EVENTS`() {
        val signals = (1..3).map { makeSignal(id = "sig-$it") }
        val events = (1..5).map { i ->
            SecurityEvent(
                source = SignalSource.APP_SCANNER,
                type = EventType.SUSPICIOUS_UPDATE,
                severity = SignalSeverity.HIGH,
                summary = "Event $i",
                signals = signals
            )
        }
        val incident = SecurityIncident(
            severity = IncidentSeverity.HIGH,
            title = "Test",
            summary = "Test",
            packageName = "com.test.app",
            events = events
        )

        val context = builder.buildIncidentContext(incident)
        val eventCount = Regex("- type:").findAll(context).count()
        assertEquals("Should limit to MAX_EVENTS", PromptBuilder.MAX_EVENTS, eventCount)
    }

    @Test
    fun `buildIncidentContext limits hypotheses to MAX_HYPOTHESES`() {
        val hypotheses = (1..6).map {
            Hypothesis("hyp_$it", "desc", 0.5, listOf("e1"))
        }
        val incident = makeIncident(hypotheses = hypotheses)

        val context = builder.buildIncidentContext(incident)
        val hypCount = Regex("- name:").findAll(context).count()
        assertEquals("Should limit to MAX_HYPOTHESES", PromptBuilder.MAX_HYPOTHESES, hypCount)
    }

    // ══════════════════════════════════════════════════════════
    //  Token estimate
    // ══════════════════════════════════════════════════════════

    @Test
    fun `estimateTokenCount gives reasonable estimate`() {
        val text = "a".repeat(400)
        assertEquals(100, builder.estimateTokenCount(text))
    }

    @Test
    fun `estimateTokenCount returns at least 1`() {
        assertEquals(1, builder.estimateTokenCount("a"))
    }

    // ══════════════════════════════════════════════════════════
    //  All constraint descriptions exist
    // ══════════════════════════════════════════════════════════

    @Test
    fun `all SafeLanguageFlags have constraint descriptions`() {
        for (flag in SafeLanguageFlag.values()) {
            assertNotNull(
                "Missing description for $flag",
                PromptBuilder.constraintDescriptions[flag]
            )
        }
    }

    // ══════════════════════════════════════════════════════════
    //  All ActionCategory values appear in schema
    // ══════════════════════════════════════════════════════════

    @Test
    fun `system instruction lists all ActionCategory values`() {
        val incident = makeIncident()
        val prompt = builder.buildPrompt(incident, emptySet())

        for (category in ActionCategory.values()) {
            assertTrue(
                "Prompt should list ${category.name}",
                prompt.contains(category.name)
            )
        }
    }

    @Test
    fun `system instruction lists all IncidentSeverity values`() {
        val incident = makeIncident()
        val prompt = builder.buildPrompt(incident, emptySet())

        for (severity in IncidentSeverity.values()) {
            assertTrue(
                "Prompt should list ${severity.name}",
                prompt.contains(severity.name)
            )
        }
    }
}
