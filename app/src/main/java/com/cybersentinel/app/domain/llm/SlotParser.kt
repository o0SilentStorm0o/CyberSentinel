package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.LlmStructuredSlots
import com.cybersentinel.app.domain.explainability.SummaryTone
import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SlotParser — robust extraction of LlmStructuredSlots from raw LLM output.
 *
 * Design principles:
 *  1. Defensive: LLM output may contain text around JSON, markdown fences, trailing tokens.
 *  2. Extract first valid JSON object from the raw output.
 *  3. Parse strictly against the slot schema — unknown fields are ignored.
 *  4. Return clear parse errors (not exceptions) for diagnostics.
 *  5. Pure JVM logic — NO org.json dependency (stubbed in Android unit tests).
 *     Uses lightweight regex-based field extraction instead.
 *     The LLM output schema is flat (no nesting beyond arrays of strings).
 */
@Singleton
class SlotParser @Inject constructor() {

    /**
     * Parse raw LLM output into structured slots.
     *
     * @param rawOutput The raw string from inference
     * @return ParseResult with either parsed slots or an error description
     */
    fun parse(rawOutput: String): ParseResult {
        if (rawOutput.isBlank()) {
            return ParseResult.Error("Empty LLM output")
        }

        // Step 1: Extract JSON from raw output
        val jsonString = extractJson(rawOutput)
            ?: return ParseResult.Error("No valid JSON object found in output")

        // Step 2: Map to LlmStructuredSlots via regex field extraction
        return try {
            val slots = mapToSlots(jsonString)
            ParseResult.Success(slots)
        } catch (e: SlotParseException) {
            ParseResult.Error("Slot mapping error: ${e.message}")
        }
    }

    // ══════════════════════════════════════════════════════════
    //  JSON extraction — find first { } block
    // ══════════════════════════════════════════════════════════

    /**
     * Extract the first well-formed JSON object from raw text.
     *
     * Handles:
     *  - JSON surrounded by text ("Here is the result: {…} Done.")
     *  - Markdown code fences (```json … ```)
     *  - Leading/trailing whitespace
     *
     * Strategy: find first '{', then find matching '}' with brace counting.
     */
    internal fun extractJson(raw: String): String? {
        // Strip markdown code fences first
        val cleaned = raw
            .replace(Regex("```json\\s*"), "")
            .replace(Regex("```\\s*"), "")
            .trim()

        val startIndex = cleaned.indexOf('{')
        if (startIndex == -1) return null

        var depth = 0
        var inString = false
        var escaped = false

        for (i in startIndex until cleaned.length) {
            val c = cleaned[i]

            if (escaped) {
                escaped = false
                continue
            }

            if (c == '\\' && inString) {
                escaped = true
                continue
            }

            if (c == '"') {
                inString = !inString
                continue
            }

            if (!inString) {
                when (c) {
                    '{' -> depth++
                    '}' -> {
                        depth--
                        if (depth == 0) {
                            return cleaned.substring(startIndex, i + 1)
                        }
                    }
                }
            }
        }

        return null // Unbalanced braces
    }

    // ══════════════════════════════════════════════════════════
    //  Regex-based field extraction (pure JVM, no org.json)
    // ══════════════════════════════════════════════════════════

    private fun mapToSlots(json: String): LlmStructuredSlots {
        // Required: assessed_severity
        val severityStr = extractStringField(json, "assessed_severity")
        val severity = parseSeverity(severityStr ?: "")
            ?: throw SlotParseException("Invalid or missing assessed_severity: '$severityStr'")

        // Required: reason_ids (array of strings)
        val reasonIds = extractStringArray(json, "reason_ids")
        if (reasonIds.isEmpty()) {
            throw SlotParseException("reason_ids is empty or missing")
        }

        // Required: action_categories (array of strings)
        val actionStrs = extractStringArray(json, "action_categories")
        val actions = actionStrs.mapNotNull { parseActionCategory(it) }
        if (actions.isEmpty()) {
            throw SlotParseException("No valid action_categories found")
        }

        // Required: confidence (double 0.0-1.0)
        val confidence = extractNumberField(json, "confidence") ?: -1.0
        if (confidence < 0.0 || confidence > 1.0) {
            throw SlotParseException("Invalid confidence: $confidence (must be 0.0-1.0)")
        }

        // Optional: summary_tone
        val toneStr = extractStringField(json, "summary_tone") ?: "neutral"
        val tone = parseSummaryTone(toneStr)

        // Optional: can_be_ignored
        val canBeIgnored = extractBooleanField(json, "can_be_ignored") ?: false

        // Optional: ignore_reason_key
        val ignoreReasonKey = extractStringField(json, "ignore_reason_key")?.takeIf {
            it.isNotBlank() && it != "null"
        }

        // Optional: notes
        val notes = extractStringField(json, "notes")?.takeIf {
            it.isNotBlank() && it != "null"
        }

        return LlmStructuredSlots(
            assessedSeverity = severity,
            summaryTone = tone,
            selectedEvidenceIds = reasonIds.take(MAX_REASON_IDS),
            recommendedActions = actions.take(MAX_ACTIONS),
            confidence = confidence,
            notes = notes?.take(MAX_NOTES_LENGTH),
            canBeIgnored = canBeIgnored,
            ignoreReasonKey = ignoreReasonKey
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Field extraction helpers
    // ══════════════════════════════════════════════════════════

    /** Extract a string field value: "key": "value" */
    internal fun extractStringField(json: String, key: String): String? {
        val regex = Regex(""""$key"\s*:\s*"([^"]*?)"""")
        return regex.find(json)?.groupValues?.get(1)
    }

    /** Extract a number field value: "key": 0.85 */
    internal fun extractNumberField(json: String, key: String): Double? {
        val regex = Regex(""""$key"\s*:\s*(-?\d+\.?\d*)""")
        return regex.find(json)?.groupValues?.get(1)?.toDoubleOrNull()
    }

    /** Extract a boolean field value: "key": true/false */
    internal fun extractBooleanField(json: String, key: String): Boolean? {
        val regex = Regex(""""$key"\s*:\s*(true|false)""")
        return regex.find(json)?.groupValues?.get(1)?.toBooleanStrictOrNull()
    }

    /** Extract a string array field: "key": ["a", "b", "c"] */
    internal fun extractStringArray(json: String, key: String): List<String> {
        val arrayRegex = Regex(""""$key"\s*:\s*\[([^\]]*)\]""")
        val arrayContent = arrayRegex.find(json)?.groupValues?.get(1) ?: return emptyList()
        val itemRegex = Regex(""""([^"]+?)"""")
        return itemRegex.findAll(arrayContent).map { it.groupValues[1] }.toList()
    }

    // ══════════════════════════════════════════════════════════
    //  Enum parsing helpers
    // ══════════════════════════════════════════════════════════

    internal fun parseSeverity(value: String): IncidentSeverity? {
        return try {
            IncidentSeverity.valueOf(value.uppercase().trim())
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    internal fun parseActionCategory(value: String): ActionCategory? {
        return try {
            ActionCategory.valueOf(value.uppercase().trim())
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    internal fun parseSummaryTone(value: String): SummaryTone {
        return when (value.lowercase().trim()) {
            "calm" -> SummaryTone.CALM
            "strict" -> SummaryTone.STRICT
            else -> SummaryTone.NEUTRAL
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Constants
    // ══════════════════════════════════════════════════════════

    companion object {
        const val MAX_REASON_IDS = 5
        const val MAX_ACTIONS = 4
        const val MAX_NOTES_LENGTH = 300
    }
}

/**
 * Parse result — either success with slots or error with description.
 */
sealed class ParseResult {
    data class Success(val slots: LlmStructuredSlots) : ParseResult()
    data class Error(val message: String) : ParseResult()

    val isSuccess: Boolean get() = this is Success
    val slotsOrNull: LlmStructuredSlots? get() = (this as? Success)?.slots
}

/**
 * Internal exception for slot mapping errors (caught and converted to ParseResult.Error).
 */
internal class SlotParseException(message: String) : Exception(message)
