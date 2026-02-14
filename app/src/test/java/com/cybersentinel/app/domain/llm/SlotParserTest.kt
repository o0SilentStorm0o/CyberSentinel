package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.SummaryTone
import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for SlotParser — robust JSON extraction and slot mapping.
 *
 * Tests verify:
 *  1. Clean JSON parse to LlmStructuredSlots
 *  2. JSON surrounded by text (model preamble/postamble)
 *  3. Markdown code fences (```json ... ```)
 *  4. Missing/invalid fields
 *  5. Enum parsing (severity, action categories, summary tone)
 *  6. Edge cases (empty, blank, no JSON, malformed)
 *  7. Length limits (max reason_ids, max actions, max notes)
 */
class SlotParserTest {

    private lateinit var parser: SlotParser

    @Before
    fun setUp() {
        parser = SlotParser()
    }

    // ══════════════════════════════════════════════════════════
    //  Clean JSON parse
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parse valid JSON extracts all fields`() {
        val json = """
        {
            "assessed_severity": "HIGH",
            "summary_tone": "strict",
            "reason_ids": ["sig-1", "sig-2"],
            "action_categories": ["UNINSTALL", "MONITOR"],
            "confidence": 0.85,
            "can_be_ignored": false,
            "ignore_reason_key": null,
            "notes": "Suspicious update detected."
        }
        """.trimIndent()

        val result = parser.parse(json)
        assertTrue(result.isSuccess)

        val slots = result.slotsOrNull!!
        assertEquals(IncidentSeverity.HIGH, slots.assessedSeverity)
        assertEquals(SummaryTone.STRICT, slots.summaryTone)
        assertEquals(listOf("sig-1", "sig-2"), slots.selectedEvidenceIds)
        assertEquals(listOf(ActionCategory.UNINSTALL, ActionCategory.MONITOR), slots.recommendedActions)
        assertEquals(0.85, slots.confidence, 0.001)
        assertFalse(slots.canBeIgnored)
        assertNull(slots.ignoreReasonKey)
        assertEquals("Suspicious update detected.", slots.notes)
    }

    @Test
    fun `parse JSON with ignore reason key`() {
        val json = """
        {
            "assessed_severity": "LOW",
            "reason_ids": ["sig-1"],
            "action_categories": ["INFORM"],
            "confidence": 0.6,
            "can_be_ignored": true,
            "ignore_reason_key": "known_developer_tool"
        }
        """.trimIndent()

        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        val slots = result.slotsOrNull!!
        assertTrue(slots.canBeIgnored)
        assertEquals("known_developer_tool", slots.ignoreReasonKey)
    }

    // ══════════════════════════════════════════════════════════
    //  Text around JSON
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parse JSON surrounded by text`() {
        val raw = """
        Here is the analysis:
        {"assessed_severity":"MEDIUM","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":0.7}
        Done.
        """.trimIndent()

        val result = parser.parse(raw)
        assertTrue("Should extract JSON from text", result.isSuccess)
        assertEquals(IncidentSeverity.MEDIUM, result.slotsOrNull!!.assessedSeverity)
    }

    @Test
    fun `parse JSON in markdown code fence`() {
        val raw = """
        ```json
        {"assessed_severity":"CRITICAL","reason_ids":["s1"],"action_categories":["UNINSTALL"],"confidence":0.95}
        ```
        """.trimIndent()

        val result = parser.parse(raw)
        assertTrue("Should handle markdown fences", result.isSuccess)
        assertEquals(IncidentSeverity.CRITICAL, result.slotsOrNull!!.assessedSeverity)
    }

    // ══════════════════════════════════════════════════════════
    //  JSON extraction edge cases
    // ══════════════════════════════════════════════════════════

    @Test
    fun `extractJson with nested braces`() {
        val raw = """prefix {"key": "val{ue}", "num": 1} suffix"""
        val json = parser.extractJson(raw)
        assertNotNull(json)
        assertTrue(json!!.startsWith("{"))
        assertTrue(json.endsWith("}"))
    }

    @Test
    fun `extractJson with escaped quotes in strings`() {
        val raw = """{"key": "value with \"quotes\"", "num": 1}"""
        val json = parser.extractJson(raw)
        assertNotNull(json)
    }

    @Test
    fun `extractJson returns null for no JSON`() {
        assertNull(parser.extractJson("No JSON here at all"))
    }

    @Test
    fun `extractJson returns null for unbalanced braces`() {
        assertNull(parser.extractJson("{\"key\": \"value\""))
    }

    // ══════════════════════════════════════════════════════════
    //  Missing / invalid fields
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parse empty input returns error`() {
        val result = parser.parse("")
        assertFalse(result.isSuccess)
        assertTrue((result as ParseResult.Error).message.contains("Empty"))
    }

    @Test
    fun `parse blank input returns error`() {
        val result = parser.parse("   \n  ")
        assertFalse(result.isSuccess)
    }

    @Test
    fun `parse missing assessed_severity returns error`() {
        val json = """{"reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":0.7}"""
        val result = parser.parse(json)
        assertFalse("Missing severity should fail", result.isSuccess)
    }

    @Test
    fun `parse invalid severity string returns error`() {
        val json = """{"assessed_severity":"MEGA","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":0.7}"""
        val result = parser.parse(json)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `parse empty reason_ids returns error`() {
        val json = """{"assessed_severity":"HIGH","reason_ids":[],"action_categories":["MONITOR"],"confidence":0.7}"""
        val result = parser.parse(json)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `parse no valid action_categories returns error`() {
        val json = """{"assessed_severity":"HIGH","reason_ids":["s1"],"action_categories":["INVALID_ACTION"],"confidence":0.7}"""
        val result = parser.parse(json)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `parse invalid confidence returns error`() {
        val json = """{"assessed_severity":"HIGH","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":1.5}"""
        val result = parser.parse(json)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `parse negative confidence returns error`() {
        val json = """{"assessed_severity":"HIGH","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":-0.1}"""
        val result = parser.parse(json)
        assertFalse(result.isSuccess)
    }

    // ══════════════════════════════════════════════════════════
    //  Enum parsing helpers
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parseSeverity handles all valid values`() {
        for (sev in IncidentSeverity.values()) {
            assertNotNull(parser.parseSeverity(sev.name))
            assertNotNull(parser.parseSeverity(sev.name.lowercase()))
        }
    }

    @Test
    fun `parseSeverity returns null for invalid`() {
        assertNull(parser.parseSeverity("UNKNOWN"))
        assertNull(parser.parseSeverity(""))
    }

    @Test
    fun `parseActionCategory handles all valid values`() {
        for (cat in ActionCategory.values()) {
            assertNotNull(parser.parseActionCategory(cat.name))
        }
    }

    @Test
    fun `parseActionCategory returns null for invalid`() {
        assertNull(parser.parseActionCategory("NUKE_FROM_ORBIT"))
    }

    @Test
    fun `parseSummaryTone defaults to NEUTRAL for unknown`() {
        assertEquals(SummaryTone.NEUTRAL, parser.parseSummaryTone("unknown"))
        assertEquals(SummaryTone.NEUTRAL, parser.parseSummaryTone(""))
    }

    @Test
    fun `parseSummaryTone handles all valid values`() {
        assertEquals(SummaryTone.CALM, parser.parseSummaryTone("calm"))
        assertEquals(SummaryTone.NEUTRAL, parser.parseSummaryTone("neutral"))
        assertEquals(SummaryTone.STRICT, parser.parseSummaryTone("strict"))
    }

    // ══════════════════════════════════════════════════════════
    //  Length limits
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parse truncates reason_ids to MAX_REASON_IDS`() {
        val ids = (1..10).map { "\"sig-$it\"" }.joinToString(",")
        val json = """{"assessed_severity":"HIGH","reason_ids":[$ids],"action_categories":["MONITOR"],"confidence":0.8}"""
        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        assertEquals(SlotParser.MAX_REASON_IDS, result.slotsOrNull!!.selectedEvidenceIds.size)
    }

    @Test
    fun `parse truncates actions to MAX_ACTIONS`() {
        val actions = ActionCategory.values().take(8).joinToString(",") { "\"${it.name}\"" }
        val json = """{"assessed_severity":"HIGH","reason_ids":["s1"],"action_categories":[$actions],"confidence":0.8}"""
        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        assertTrue(result.slotsOrNull!!.recommendedActions.size <= SlotParser.MAX_ACTIONS)
    }

    @Test
    fun `parse truncates long notes`() {
        val longNotes = "x".repeat(500)
        val json = """{"assessed_severity":"HIGH","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":0.8,"notes":"$longNotes"}"""
        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        assertTrue(result.slotsOrNull!!.notes!!.length <= SlotParser.MAX_NOTES_LENGTH)
    }

    // ══════════════════════════════════════════════════════════
    //  Optional fields default correctly
    // ══════════════════════════════════════════════════════════

    @Test
    fun `parse with minimal fields uses defaults`() {
        val json = """{"assessed_severity":"MEDIUM","reason_ids":["s1"],"action_categories":["MONITOR"],"confidence":0.7}"""
        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        val slots = result.slotsOrNull!!
        assertEquals(SummaryTone.NEUTRAL, slots.summaryTone)
        assertFalse(slots.canBeIgnored)
        assertNull(slots.ignoreReasonKey)
        assertNull(slots.notes)
    }

    // ══════════════════════════════════════════════════════════
    //  ParseResult properties
    // ══════════════════════════════════════════════════════════

    @Test
    fun `ParseResult Error has null slotsOrNull`() {
        val result = ParseResult.Error("test error")
        assertFalse(result.isSuccess)
        assertNull(result.slotsOrNull)
    }

    @Test
    fun `ParseResult Success has non-null slotsOrNull`() {
        val json = """{"assessed_severity":"LOW","reason_ids":["s1"],"action_categories":["INFORM"],"confidence":0.5}"""
        val result = parser.parse(json)
        assertTrue(result.isSuccess)
        assertNotNull(result.slotsOrNull)
    }
}
