package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.SecurityIncident
import com.cybersentinel.app.domain.security.SignalType
import com.cybersentinel.app.domain.security.TrustRiskModel
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PolicyGuard — evidence-based policy constraint engine.
 *
 * NOT a simple banned-word filter. Each constraint is tied to specific evidence checks.
 *
 * Core principle: Strong claims require HARD evidence.
 *  - "Malware" → requires HARD findings (CERT_MISMATCH, DEBUG_SIGNATURE, HOOKING_FRAMEWORK, etc.)
 *  - "Compromised" → requires HARD + hypothesis confidence ≥ 0.7
 *  - "Factory reset" → requires CRITICAL severity + HARD evidence
 *  - "Virus" → ALWAYS blocked (not an Android concept)
 *  - "Spying" → requires confirmed stalkerware pattern with HARD evidence
 *  - Alarmist framing → blocked for INFO/LOW severity
 *
 * PolicyGuard operates in two modes:
 *  1. Pre-generation: Determines which SafeLanguageFlags apply to the incident
 *  2. Post-validation: Validates an ExplanationAnswer and fixes violations
 *
 * Thread safety: Stateless, safe for concurrent use.
 */
@Singleton
class PolicyGuard @Inject constructor() {

    // ══════════════════════════════════════════════════════════
    //  Evidence analysis
    // ══════════════════════════════════════════════════════════

    /** HARD FindingTypes that constitute strong evidence of malicious intent */
    private val malwareHardEvidence = setOf(
        TrustRiskModel.FindingType.DEBUG_SIGNATURE,
        TrustRiskModel.FindingType.SIGNATURE_MISMATCH,
        TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE,
        TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING,
        TrustRiskModel.FindingType.INSTALLER_ANOMALY,
        TrustRiskModel.FindingType.VERSION_ROLLBACK,
        TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED
    )

    /** SignalTypes that indicate confirmed stalkerware pattern */
    private val stalkerwareSignals = setOf(
        SignalType.COMBO_DETECTED,
        SignalType.SPECIAL_ACCESS_ENABLED
    )

    /** Minimum hypothesis confidence to allow "compromised" framing */
    private val compromiseConfidenceThreshold = 0.7

    /** Minimum hypothesis confidence to allow "malware" framing */
    private val malwareConfidenceThreshold = 0.6

    // ══════════════════════════════════════════════════════════
    //  Pre-generation: Determine active constraints
    // ══════════════════════════════════════════════════════════

    /**
     * Analyze the incident and determine which SafeLanguageFlags apply.
     *
     * This is called BEFORE generating an explanation so the engine knows
     * which claims/framings are forbidden.
     *
     * @param incident The security incident to analyze
     * @return Set of active language constraints
     */
    fun determineConstraints(incident: SecurityIncident): Set<SafeLanguageFlag> {
        val flags = mutableSetOf<SafeLanguageFlag>()

        val hardFindingTypes = extractHardFindingTypes(incident)
        val topConfidence = incident.hypotheses.maxOfOrNull { it.confidence } ?: 0.0
        val hasHardMalwareEvidence = hardFindingTypes.any { it in malwareHardEvidence }
        val hasStalkerwareHardEvidence = hasConfirmedStalkerwarePattern(incident)

        // ── Rule 1: NO_VIRUS_CLAIM — always active (Android doesn't have "viruses") ──
        flags.add(SafeLanguageFlag.NO_VIRUS_CLAIM)

        // ── Rule 2: NO_MALWARE_CLAIM — no HARD evidence of malicious intent ──
        if (!hasHardMalwareEvidence || topConfidence < malwareConfidenceThreshold) {
            flags.add(SafeLanguageFlag.NO_MALWARE_CLAIM)
        }

        // ── Rule 3: NO_COMPROMISE_CLAIM — no HARD evidence + high confidence ──
        if (!hasHardMalwareEvidence || topConfidence < compromiseConfidenceThreshold) {
            flags.add(SafeLanguageFlag.NO_COMPROMISE_CLAIM)
        }

        // ── Rule 4: NO_FACTORY_RESET — not CRITICAL severity or no HARD evidence ──
        if (incident.severity != IncidentSeverity.CRITICAL || !hasHardMalwareEvidence) {
            flags.add(SafeLanguageFlag.NO_FACTORY_RESET)
        }

        // ── Rule 5: NO_SPYING_CLAIM — no confirmed stalkerware pattern ──
        if (!hasStalkerwareHardEvidence) {
            flags.add(SafeLanguageFlag.NO_SPYING_CLAIM)
        }

        // ── Rule 6: NO_ALARMIST_FRAMING — severity is INFO or LOW ──
        if (incident.severity in setOf(IncidentSeverity.INFO, IncidentSeverity.LOW)) {
            flags.add(SafeLanguageFlag.NO_ALARMIST_FRAMING)
        }

        return flags
    }

    // ══════════════════════════════════════════════════════════
    //  Post-validation: Validate and fix an ExplanationAnswer
    // ══════════════════════════════════════════════════════════

    /**
     * Validate an ExplanationAnswer against policy constraints.
     *
     * Returns a corrected answer with:
     *  - Factory reset actions removed if NO_FACTORY_RESET is active
     *  - Severity downgraded if evidence doesn't support it
     *  - Policy violation count updated
     *  - SafeLanguageFlags attached
     *
     * @param answer The explanation to validate
     * @param incident The original incident (for evidence checking)
     * @return Corrected ExplanationAnswer
     */
    fun validate(answer: ExplanationAnswer, incident: SecurityIncident): ExplanationAnswer {
        val constraints = determineConstraints(incident)
        var violations = 0
        var correctedActions = answer.actions
        var correctedSeverity = answer.severity

        // ── Enforce NO_FACTORY_RESET: Remove factory reset actions ──
        if (SafeLanguageFlag.NO_FACTORY_RESET in constraints) {
            val before = correctedActions.size
            correctedActions = correctedActions.filter {
                it.actionCategory != ActionCategory.FACTORY_RESET
            }.mapIndexed { idx, step -> step.copy(stepNumber = idx + 1) }
            if (correctedActions.size < before) violations++
        }

        // ── Enforce NO_ALARMIST_FRAMING: Cap severity at MEDIUM for INFO/LOW incidents ──
        if (SafeLanguageFlag.NO_ALARMIST_FRAMING in constraints) {
            if (correctedSeverity in setOf(IncidentSeverity.CRITICAL, IncidentSeverity.HIGH)) {
                correctedSeverity = IncidentSeverity.MEDIUM
                violations++
            }
        }

        // ── Enforce evidence-severity consistency ──
        // If no HARD evidence at all, cap at HIGH (cannot be CRITICAL)
        val hardFindingTypes = extractHardFindingTypes(incident)
        if (hardFindingTypes.isEmpty() && correctedSeverity == IncidentSeverity.CRITICAL) {
            correctedSeverity = IncidentSeverity.HIGH
            violations++
        }

        return answer.copy(
            severity = correctedSeverity,
            actions = correctedActions,
            safeLanguageFlags = constraints,
            policyViolationsFound = violations
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Evidence extraction helpers
    // ══════════════════════════════════════════════════════════

    /**
     * Extract HARD FindingTypes referenced in the incident's signals.
     *
     * Maps signal types to FindingTypes and filters for HARD hardness.
     * This is the bridge between the incident pipeline and the trust model.
     */
    fun extractHardFindingTypes(incident: SecurityIncident): Set<TrustRiskModel.FindingType> {
        val signalTypes = incident.events.flatMap { event ->
            event.signals.map { it.type }
        }.toSet()

        return signalTypeToFindingType
            .filter { (signalType, _) -> signalType in signalTypes }
            .map { (_, findingType) -> findingType }
            .filter { it.hardness == TrustRiskModel.FindingHardness.HARD }
            .toSet()
    }

    /**
     * Check if the incident has a confirmed stalkerware pattern.
     *
     * Requires: COMBO_DETECTED signal + SPECIAL_ACCESS_ENABLED signal + HARD evidence
     */
    private fun hasConfirmedStalkerwarePattern(incident: SecurityIncident): Boolean {
        val signalTypes = incident.events.flatMap { event ->
            event.signals.map { it.type }
        }.toSet()

        val hasCombo = SignalType.COMBO_DETECTED in signalTypes
        val hasSpecialAccess = SignalType.SPECIAL_ACCESS_ENABLED in signalTypes
        val hasHardEvidence = extractHardFindingTypes(incident).isNotEmpty()

        return hasCombo && hasSpecialAccess && hasHardEvidence
    }

    /**
     * Check if a specific action category is allowed given the constraints.
     */
    fun isActionAllowed(action: ActionCategory, constraints: Set<SafeLanguageFlag>): Boolean {
        if (action == ActionCategory.FACTORY_RESET && SafeLanguageFlag.NO_FACTORY_RESET in constraints) {
            return false
        }
        return true
    }

    companion object {
        /**
         * Mapping from SignalType to FindingType for evidence extraction.
         *
         * Not all SignalTypes map to FindingTypes — only those that have
         * direct equivalents in the trust model.
         */
        val signalTypeToFindingType: Map<SignalType, TrustRiskModel.FindingType> = mapOf(
            SignalType.CERT_CHANGE to TrustRiskModel.FindingType.SIGNATURE_MISMATCH,
            SignalType.VERSION_ROLLBACK to TrustRiskModel.FindingType.VERSION_ROLLBACK,
            SignalType.INSTALLER_CHANGE to TrustRiskModel.FindingType.INSTALLER_ANOMALY,
            SignalType.HIGH_RISK_PERM_ADDED to TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED,
            SignalType.DEBUG_SIGNATURE to TrustRiskModel.FindingType.DEBUG_SIGNATURE,
            SignalType.SUSPICIOUS_NATIVE_LIB to TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB
        )
    }
}
