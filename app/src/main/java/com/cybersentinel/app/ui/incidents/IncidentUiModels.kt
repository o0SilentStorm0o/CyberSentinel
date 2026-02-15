package com.cybersentinel.app.ui.incidents

import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.IncidentStatus

/**
 * UI models for the incident-first screens.
 *
 * These are pure presentation models — no domain logic, no Android framework deps.
 * Produced by mappers from domain objects. Consumed by Compose screens.
 *
 * Sprint UI-1: Incident list + detail MVP.
 */

// ══════════════════════════════════════════════════════════
//  List card model
// ══════════════════════════════════════════════════════════

/**
 * Lightweight model for one card in the incident list.
 */
data class IncidentCardModel(
    val incidentId: String,
    val title: String,
    /** One-sentence summary for the list card */
    val shortSummary: String,
    val severity: IncidentSeverity,
    val status: IncidentStatus,
    /** Up to 2 package names shown, plus overflow count */
    val displayPackages: List<String>,
    /** Total affected packages (may be > displayPackages.size) */
    val totalAffectedPackages: Int,
    val createdAt: Long,
    /** True if at least one hypothesis is stalkerware/dropper/overlay */
    val isThreat: Boolean
) {
    /** "+N" label for overflow packages, or null if all fit */
    val overflowLabel: String?
        get() {
            val overflow = totalAffectedPackages - displayPackages.size
            return if (overflow > 0) "+$overflow" else null
        }
}

// ══════════════════════════════════════════════════════════
//  Detail model
// ══════════════════════════════════════════════════════════

/**
 * Full detail model for the incident detail screen.
 * Maps 1:1 to the 5 UI sections defined in the spec.
 */
data class IncidentDetailModel(
    val incidentId: String,
    val title: String,
    val severity: IncidentSeverity,
    val status: IncidentStatus,
    val createdAt: Long,

    // Section 1: "Co se děje"
    val whatHappened: String,

    // Section 2: "Proč si to myslíme" (max 3 reasons)
    val reasons: List<ReasonUiModel>,

    // Section 3: "Co udělat teď" (max 3 actions)
    val actions: List<ActionUiModel>,

    // Section 4: "Kdy to ignorovat"
    val whenToIgnore: String?,

    // Section 5: "Technické detaily" (collapsed by default)
    val technicalDetails: TechnicalDetailsModel,

    // Engine attribution
    val engineSourceLabel: String?,
    val isBusyFallback: Boolean
)

/**
 * Single evidence reason for the detail screen.
 */
data class ReasonUiModel(
    val evidenceId: String,
    val text: String,
    val severity: IncidentSeverity,
    val findingTag: String,
    val isHardEvidence: Boolean
)

/**
 * Single action step for the detail screen.
 */
data class ActionUiModel(
    val stepNumber: Int,
    val title: String,
    val description: String,
    val actionCategory: ActionCategory,
    val targetPackage: String?,
    val isUrgent: Boolean
)

/**
 * Collapsed "technical details" section data.
 */
data class TechnicalDetailsModel(
    /** Raw signal summaries */
    val signals: List<String>,
    /** Hypothesis names + confidence */
    val hypotheses: List<String>,
    /** Affected packages */
    val affectedPackages: List<String>,
    /** Event metadata as key-value pairs */
    val metadata: Map<String, String>
)

// ══════════════════════════════════════════════════════════
//  Explanation state
// ══════════════════════════════════════════════════════════

/**
 * State of the "explain" operation (on-demand LLM / template).
 */
sealed class ExplanationUiState {
    /** No explanation requested yet */
    data object Idle : ExplanationUiState()
    /** Explanation in progress */
    data class Loading(val message: String = "AI připravuje vysvětlení…") : ExplanationUiState()
    /** Explanation ready */
    data class Ready(val detail: IncidentDetailModel) : ExplanationUiState()
    /** Explanation failed (should not happen — template fallback always works) */
    data class Error(val message: String) : ExplanationUiState()
}

// ══════════════════════════════════════════════════════════
//  AI / Model status
// ══════════════════════════════════════════════════════════

/**
 * UI model for the "AI & Model" settings/status screen.
 */
data class AiStatusUiModel(
    /** Display label for current model state */
    val modelStateLabel: String,
    /** Capability tier label */
    val tierLabel: String,
    /** True if LLM gate is currently open */
    val llmAvailable: Boolean,
    /** Human-readable reason why LLM is or isn't available */
    val gateReason: String,
    /** Model download progress (0.0 - 1.0), null if not downloading */
    val downloadProgress: Float?,
    /** Model file size for download CTA */
    val modelSizeMb: Long?,
    /** Available device storage in MB */
    val availableStorageMb: Long?,
    /** True if self-test has been run */
    val selfTestCompleted: Boolean,
    /** Production ready result from last self-test */
    val isProductionReady: Boolean?,
    /** Self-test summary text */
    val selfTestSummary: String?,
    /** True if kill switch is active */
    val killSwitchActive: Boolean,
    /** User LLM preference toggle state */
    val userLlmEnabled: Boolean
)
