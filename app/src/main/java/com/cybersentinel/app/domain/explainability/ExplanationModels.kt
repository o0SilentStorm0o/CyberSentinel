package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.AppFeatureVector
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.SecurityIncident
import java.util.Locale

/**
 * Explainability Models — unified output schema for both Template and LLM engines.
 *
 * Architecture: The same ExplanationAnswer is produced whether the engine is:
 *  - TemplateExplanationEngine (deterministic Czech templates — baseline quality)
 *  - LLM engine (fills structured slots → template renderer generates Czech)
 *
 * The LLM never generates free-form Czech text. Instead it fills structured slots
 * (severity assessment, evidence selection, action prioritization) and the
 * TemplateExplanationEngine renders those slots into Czech. This guarantees:
 *  1. Consistent language quality regardless of model capability
 *  2. PolicyGuard can validate structured slots before rendering
 *  3. Template engine doubles as ground truth for measuring LLM quality
 *
 * All fields are deterministic and auditable — no opaque LLM strings in the output.
 */

// ══════════════════════════════════════════════════════════
//  Request
// ══════════════════════════════════════════════════════════

/**
 * Input to any ExplanationEngine.
 *
 * @param incident The security incident to explain
 * @param appFeatureVector Optional app knowledge for richer context
 * @param userQuestion Optional user question for future interactive mode
 * @param locale Target locale (default Czech)
 */
data class ExplanationRequest(
    val incident: SecurityIncident,
    val appFeatureVector: AppFeatureVector? = null,
    val userQuestion: String? = null,
    val locale: Locale = Locale("cs", "CZ")
)

// ══════════════════════════════════════════════════════════
//  Response
// ══════════════════════════════════════════════════════════

/**
 * The unified explanation output. Produced by both Template and LLM engines.
 *
 * This is what the UI renders. Every field is structured — no raw LLM text.
 *
 * @param incidentId Reference to the explained incident
 * @param severity Assessed severity (may differ from incident if PolicyGuard downgrades)
 * @param summary Human-readable summary in target locale
 * @param reasons Ordered list of evidence-backed reasons (most important first)
 * @param actions Ordered list of actionable steps for the user
 * @param whenToIgnore Optional guidance on when this finding can be safely ignored
 * @param confidence Engine's confidence in this explanation (0.0-1.0)
 * @param safeLanguageFlags Active language constraints applied by PolicyGuard
 * @param engineSource Which engine produced this explanation
 * @param policyViolationsFound Number of policy violations caught and corrected
 */
data class ExplanationAnswer(
    val incidentId: String,
    val severity: IncidentSeverity,
    val summary: String,
    val reasons: List<EvidenceReason>,
    val actions: List<ActionStep>,
    val whenToIgnore: String? = null,
    val confidence: Double,
    val safeLanguageFlags: Set<SafeLanguageFlag> = emptySet(),
    val engineSource: EngineSource = EngineSource.TEMPLATE,
    val policyViolationsFound: Int = 0,
    /**
     * C2-2.7: True when this answer is a template fallback triggered by LLM "busy" (single-flight).
     * This is NOT an LLM failure — it means another inference was already running.
     * UX should present this as "explanation is being generated, using fast response"
     * rather than an error. Stability metrics should NOT count this as an LLM error.
     */
    val isBusyFallback: Boolean = false
) {
    /** True if this explanation has actionable steps beyond just monitoring */
    val hasActionableSteps: Boolean
        get() = actions.any { it.actionCategory != ActionCategory.MONITOR && it.actionCategory != ActionCategory.INFORM }

    /** The top reason (most important), or null if no reasons */
    val primaryReason: EvidenceReason?
        get() = reasons.firstOrNull()

    /** The most urgent action, or null if no actions */
    val primaryAction: ActionStep?
        get() = actions.firstOrNull()
}

// ══════════════════════════════════════════════════════════
//  Structured components
// ══════════════════════════════════════════════════════════

/**
 * A single evidence-backed reason explaining WHY the finding matters.
 *
 * Each reason references specific evidence from the incident's signals/events,
 * making it auditable and verifiable.
 *
 * @param evidenceId Reference to the supporting signal/event ID
 * @param text Human-readable reason text in target locale
 * @param severity How serious this specific reason is
 * @param findingTag Short machine-readable tag for the finding (e.g., "CERT_MISMATCH", "SIDELOAD")
 * @param isHardEvidence True if this reason is backed by HARD evidence (FindingHardness.HARD)
 */
data class EvidenceReason(
    val evidenceId: String,
    val text: String,
    val severity: IncidentSeverity,
    val findingTag: String,
    val isHardEvidence: Boolean = false
)

/**
 * A single actionable step the user can take.
 *
 * Steps are ordered by priority (most urgent first).
 *
 * @param stepNumber Display order (1-based)
 * @param actionCategory Machine-readable action type (maps to ActionCategory)
 * @param title Short action title in target locale
 * @param description Detailed instruction in target locale
 * @param targetPackage Package to act on (if app-level action)
 * @param isUrgent True if this action should be highlighted/emphasized in UI
 */
data class ActionStep(
    val stepNumber: Int,
    val actionCategory: ActionCategory,
    val title: String,
    val description: String,
    val targetPackage: String? = null,
    val isUrgent: Boolean = false
)

// ══════════════════════════════════════════════════════════
//  Enums
// ══════════════════════════════════════════════════════════

/**
 * Safe language constraints enforced by PolicyGuard.
 *
 * These flags indicate which language restrictions are ACTIVE for this explanation.
 * When a flag is present, the corresponding claim/framing was suppressed.
 *
 * Design: Evidence-based, not simple banned words.
 * Each flag maps to a policy rule that checks HARD evidence presence.
 */
enum class SafeLanguageFlag(val description: String) {
    /** Cannot claim "malware" — no HARD evidence of malicious intent */
    NO_MALWARE_CLAIM("Nelze tvrdit přítomnost malwaru bez tvrdého důkazu"),
    /** Cannot claim "virus" — never appropriate for Android context */
    NO_VIRUS_CLAIM("Termín 'virus' není vhodný pro Android kontext"),
    /** Cannot claim device is "compromised" — insufficient evidence */
    NO_COMPROMISE_CLAIM("Nelze tvrdit kompromitaci zařízení bez tvrdého důkazu"),
    /** Cannot recommend factory reset — disproportionate without HARD evidence */
    NO_FACTORY_RESET("Nelze doporučit tovární nastavení bez kritického důkazu"),
    /** Cannot claim "spying" — stalkerware pattern alone is insufficient */
    NO_SPYING_CLAIM("Nelze tvrdit sledování bez potvrzeného stalkerware vzoru"),
    /** Cannot use alarmist framing — severity doesn't justify it */
    NO_ALARMIST_FRAMING("Nelze použít alarmistický tón pro tento stupeň závažnosti")
}

/**
 * Which engine produced the explanation.
 *
 * Used for quality tracking, A/B testing, and fallback attribution.
 */
enum class EngineSource {
    /** Deterministic Czech template engine — baseline quality */
    TEMPLATE,
    /** LLM-assisted structured slot filling + template rendering */
    LLM_ASSISTED,
    /** Fallback from LLM to template (LLM failed or was gated) */
    LLM_FALLBACK_TO_TEMPLATE
}

// ══════════════════════════════════════════════════════════
//  LLM structured slots (for future Sprint C)
// ══════════════════════════════════════════════════════════

/**
 * Structured slots that the LLM fills. NOT free-form text.
 *
 * The LLM receives incident data and returns these structured decisions.
 * The TemplateExplanationEngine then renders them into Czech.
 *
 * This is the contract between LLM inference and template rendering.
 * Keeping it here so both engines share the same schema from day one.
 */
data class LlmStructuredSlots(
    /** LLM's severity assessment (may be validated/overridden by PolicyGuard) */
    val assessedSeverity: IncidentSeverity,
    /** Summary tone directive: calm / neutral / strict */
    val summaryTone: SummaryTone = SummaryTone.NEUTRAL,
    /** Ordered evidence IDs the LLM considers most relevant */
    val selectedEvidenceIds: List<String>,
    /** Ordered action categories the LLM recommends */
    val recommendedActions: List<ActionCategory>,
    /** LLM's confidence in its assessment (0.0-1.0) */
    val confidence: Double,
    /** Optional: short free-text notes (1-2 sentences max, may be empty) */
    val notes: String? = null,
    /** Optional: LLM's reasoning chain (for debugging/audit, not shown to user) */
    val reasoningTrace: String? = null,
    /** Whether the LLM thinks this can be safely ignored */
    val canBeIgnored: Boolean = false,
    /** Ignore reason key (maps to template) */
    val ignoreReasonKey: String? = null
)

/**
 * Summary tone directive from LLM — controls template rendering style.
 */
enum class SummaryTone {
    /** Reassuring, low urgency */
    CALM,
    /** Factual, balanced */
    NEUTRAL,
    /** Direct, emphasizes risk */
    STRICT
}
