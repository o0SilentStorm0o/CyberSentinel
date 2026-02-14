package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.LlmStructuredSlots
import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.SecurityIncident
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SlotValidator — validates parsed LlmStructuredSlots against the incident evidence.
 *
 * Catches LLM hallucinations:
 *  1. reason_ids must reference actual evidence IDs from the incident
 *  2. action_categories must be from the valid set
 *  3. Confidence must be in bounds
 *  4. Severity must not wildly exceed incident severity without reason
 *  5. notes length limit enforced
 *
 * Validation can either REJECT or REPAIR:
 *  - REJECT: return validation error → fallback to template
 *  - REPAIR: strip invalid entries, clamp values → continue with cleaned slots
 *
 * Default mode is REPAIR — we prefer degraded LLM output over full fallback
 * as long as the core structure is intact.
 */
@Singleton
class SlotValidator @Inject constructor() {

    /**
     * Validate and optionally repair LLM-parsed slots against the incident.
     *
     * @param slots The parsed slots from SlotParser
     * @param incident The incident that was being explained
     * @param mode STRICT rejects on any issue, LENIENT repairs what it can
     * @return ValidationResult with either valid slots or rejection reason
     */
    fun validate(
        slots: LlmStructuredSlots,
        incident: SecurityIncident,
        mode: ValidationMode = ValidationMode.LENIENT
    ): ValidationResult {
        val issues = mutableListOf<ValidationIssue>()

        // Collect all valid evidence IDs from the incident
        val validEvidenceIds = collectEvidenceIds(incident)

        // 1. Validate reason_ids reference real evidence
        val validReasonIds = slots.selectedEvidenceIds.filter { it in validEvidenceIds }
        val invalidReasonIds = slots.selectedEvidenceIds.filter { it !in validEvidenceIds }
        if (invalidReasonIds.isNotEmpty()) {
            issues.add(
                ValidationIssue(
                    field = "selectedEvidenceIds",
                    severity = IssueSeverity.WARNING,
                    message = "Removed ${invalidReasonIds.size} hallucinated evidence IDs: ${invalidReasonIds.take(3)}"
                )
            )
        }
        if (validReasonIds.isEmpty()) {
            issues.add(
                ValidationIssue(
                    field = "selectedEvidenceIds",
                    severity = IssueSeverity.CRITICAL,
                    message = "No valid evidence IDs remain after filtering"
                )
            )
        }

        // 2. Validate action categories
        val validActions = slots.recommendedActions.filter { it in ActionCategory.values() }
        if (validActions.isEmpty() && slots.recommendedActions.isNotEmpty()) {
            issues.add(
                ValidationIssue(
                    field = "recommendedActions",
                    severity = IssueSeverity.CRITICAL,
                    message = "No valid action categories"
                )
            )
        }

        // 3. Validate confidence bounds
        val clampedConfidence = slots.confidence.coerceIn(0.0, 1.0)
        if (clampedConfidence != slots.confidence) {
            issues.add(
                ValidationIssue(
                    field = "confidence",
                    severity = IssueSeverity.WARNING,
                    message = "Confidence clamped from ${slots.confidence} to $clampedConfidence"
                )
            )
        }

        // 4. Severity escalation check: LLM can't escalate more than 1 level above incident
        val severityOk = checkSeverityEscalation(slots.assessedSeverity, incident.severity)
        val finalSeverity = if (severityOk) slots.assessedSeverity else incident.severity
        if (!severityOk) {
            issues.add(
                ValidationIssue(
                    field = "assessedSeverity",
                    severity = IssueSeverity.WARNING,
                    message = "Severity ${slots.assessedSeverity} exceeds incident ${incident.severity} by >1 level, clamped"
                )
            )
        }

        // 5. Notes length
        val trimmedNotes = slots.notes?.take(MAX_NOTES_LENGTH)
        if (slots.notes != null && slots.notes.length > MAX_NOTES_LENGTH) {
            issues.add(
                ValidationIssue(
                    field = "notes",
                    severity = IssueSeverity.INFO,
                    message = "Notes truncated from ${slots.notes.length} to $MAX_NOTES_LENGTH chars"
                )
            )
        }

        // 6. ignoreReasonKey validation
        val validIgnoreKey = slots.ignoreReasonKey?.takeIf { it in VALID_IGNORE_KEYS }
        if (slots.ignoreReasonKey != null && validIgnoreKey == null) {
            issues.add(
                ValidationIssue(
                    field = "ignoreReasonKey",
                    severity = IssueSeverity.WARNING,
                    message = "Invalid ignore reason key: '${slots.ignoreReasonKey}'"
                )
            )
        }

        // Decision: reject or repair?
        val hasCritical = issues.any { it.severity == IssueSeverity.CRITICAL }

        if (mode == ValidationMode.STRICT && issues.isNotEmpty()) {
            return ValidationResult.Rejected(
                issues = issues,
                reason = "Strict mode: ${issues.size} issues found"
            )
        }

        if (hasCritical && validReasonIds.isEmpty()) {
            return ValidationResult.Rejected(
                issues = issues,
                reason = "No valid evidence IDs — cannot produce meaningful explanation"
            )
        }

        // Repair: build cleaned slots
        val repairedSlots = slots.copy(
            assessedSeverity = finalSeverity,
            selectedEvidenceIds = validReasonIds,
            recommendedActions = validActions,
            confidence = clampedConfidence,
            notes = trimmedNotes,
            ignoreReasonKey = validIgnoreKey,
            canBeIgnored = if (validIgnoreKey == null) false else slots.canBeIgnored
        )

        return if (issues.isEmpty()) {
            ValidationResult.Valid(repairedSlots)
        } else {
            ValidationResult.Repaired(repairedSlots, issues)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Evidence ID collection
    // ══════════════════════════════════════════════════════════

    /**
     * Collect all valid evidence IDs from the incident hierarchy.
     * Evidence = signal IDs + event IDs.
     */
    internal fun collectEvidenceIds(incident: SecurityIncident): Set<String> {
        val ids = mutableSetOf<String>()
        for (event in incident.events) {
            ids.add(event.id)
            for (signal in event.signals) {
                ids.add(signal.id)
            }
        }
        return ids
    }

    /**
     * Check if LLM severity escalation is reasonable.
     *
     * Rule: LLM can escalate at most 1 level above the incident's severity.
     * e.g., incident=MEDIUM → LLM can say HIGH but not CRITICAL.
     */
    internal fun checkSeverityEscalation(
        llmSeverity: IncidentSeverity,
        incidentSeverity: IncidentSeverity
    ): Boolean {
        val llmOrdinal = llmSeverity.ordinal   // CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, INFO=4
        val incOrdinal = incidentSeverity.ordinal
        // LLM says more severe = lower ordinal. Check diff.
        return (incOrdinal - llmOrdinal) <= 1
    }

    // ══════════════════════════════════════════════════════════
    //  Constants
    // ══════════════════════════════════════════════════════════

    companion object {
        const val MAX_NOTES_LENGTH = 300

        val VALID_IGNORE_KEYS = setOf(
            "user_initiated_update",
            "known_developer_tool",
            "corporate_profile",
            "power_user_sideload",
            "vpn_by_choice"
        )
    }
}

// ══════════════════════════════════════════════════════════
//  Validation types
// ══════════════════════════════════════════════════════════

enum class ValidationMode {
    /** Reject on any issue */
    STRICT,
    /** Repair what can be repaired, reject only on critical structural issues */
    LENIENT
}

sealed class ValidationResult {
    /** Slots are valid as-is */
    data class Valid(val slots: LlmStructuredSlots) : ValidationResult()
    /** Slots had issues but were repaired */
    data class Repaired(val slots: LlmStructuredSlots, val issues: List<ValidationIssue>) : ValidationResult()
    /** Slots could not be repaired — fallback to template */
    data class Rejected(val issues: List<ValidationIssue>, val reason: String) : ValidationResult()

    val isUsable: Boolean get() = this is Valid || this is Repaired
    val slotsOrNull: LlmStructuredSlots? get() = when (this) {
        is Valid -> slots
        is Repaired -> slots
        is Rejected -> null
    }
}

data class ValidationIssue(
    val field: String,
    val severity: IssueSeverity,
    val message: String
)

enum class IssueSeverity {
    /** Informational — no action needed */
    INFO,
    /** Warning — repaired automatically */
    WARNING,
    /** Critical — may cause rejection */
    CRITICAL
}
