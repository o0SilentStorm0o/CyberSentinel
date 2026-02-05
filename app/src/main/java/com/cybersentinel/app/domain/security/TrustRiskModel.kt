package com.cybersentinel.app.domain.security

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Trust & Risk Model — combines TrustScore with RiskScore to produce a final verdict.
 *
 * Core principle: **Whitelist is NOT immunity, it's weight reduction.**
 *
 * Findings are classified as:
 *  - HARD: Never suppressed by trust. Debug cert, signature mismatch,
 *    baseline anomaly, integrity fail + hooking, installer anomaly.
 *  - SOFT: Trust can reduce their severity. Exported components,
 *    over-privileged heuristic, old target SDK.
 *
 * Final severity = f(RiskScore, TrustScore):
 *  - High risk + low trust  → show prominently
 *  - High risk + high trust → show, but softer wording (soft findings only)
 *  - Low risk + any trust   → collapsed / hidden
 *
 * System apps get a separate evaluation mode:
 *  - Default: collapsed section, don't alarm about normal system behavior
 *  - Flagged in main list ONLY on strong anomalies (signature change, new component, integrity fail)
 */
@Singleton
class TrustRiskModel @Inject constructor() {

    // ──────────────────────────────────────────────────────────
    //  Finding classification
    // ──────────────────────────────────────────────────────────

    /**
     * Whether a finding is "hard" (never suppressed) or "soft" (trust can reduce weight).
     */
    enum class FindingHardness {
        /** Never suppressed by trust. Always shown regardless of TrustScore. */
        HARD,
        /** Trust can reduce severity/weight. May be hidden for high-trust apps. */
        SOFT
    }

    /**
     * All recognizable finding types with their hardness classification.
     */
    enum class FindingType(val hardness: FindingHardness) {
        // ── HARD findings ──
        /** Debug cert on a "release" app */
        DEBUG_SIGNATURE(FindingHardness.HARD),
        /** Cert doesn't match expected (possible re-sign/supply-chain) */
        SIGNATURE_MISMATCH(FindingHardness.HARD),
        /** Signature changed vs. persisted baseline */
        BASELINE_SIGNATURE_CHANGE(FindingHardness.HARD),
        /** New system component appeared outside OTA */
        BASELINE_NEW_SYSTEM_APP(FindingHardness.HARD),
        /** Device integrity fail (unlocked bootloader / root) + hooking indicators */
        INTEGRITY_FAIL_WITH_HOOKING(FindingHardness.HARD),
        /** Installed from unexpected source (sideload) for a trusted-looking app */
        INSTALLER_ANOMALY(FindingHardness.HARD),

        // ── SOFT findings ──
        /** App has more permissions than its category needs */
        OVER_PRIVILEGED(FindingHardness.SOFT),
        /** Exported components without protection */
        EXPORTED_COMPONENTS(FindingHardness.SOFT),
        /** Target SDK too old */
        OLD_TARGET_SDK(FindingHardness.SOFT),
        /** Native libs with suspicious names (generic heuristic) */
        SUSPICIOUS_NATIVE_LIB(FindingHardness.SOFT),
        /** Critical permission granted (e.g., background location) */
        CRITICAL_PERMISSION(FindingHardness.SOFT)
    }

    // ──────────────────────────────────────────────────────────
    //  AppVerdict — final combined judgment
    // ──────────────────────────────────────────────────────────

    /**
     * Final combined Trust+Risk verdict for one app.
     */
    data class AppVerdict(
        val packageName: String,
        val trustScore: Int,      // 0-100 from TrustEvidenceEngine
        val riskScore: Int,       // 0-100 from heuristics
        val effectiveRisk: EffectiveRisk,
        val verdictLabel: String,
        val verdictDescription: String,
        val shouldShowInMainList: Boolean,
        val isSystemComponent: Boolean,
        /** Which findings were kept after trust adjustment */
        val adjustedFindings: List<AdjustedFinding>
    )

    data class AdjustedFinding(
        val findingType: FindingType,
        val originalSeverity: AppSecurityScanner.RiskLevel,
        val adjustedSeverity: AppSecurityScanner.RiskLevel,
        val hardness: FindingHardness,
        val wasDowngraded: Boolean,
        val title: String
    )

    enum class EffectiveRisk {
        /** Genuine threat — hard findings present or high risk + low trust */
        CRITICAL,
        /** Worth reviewing — medium risk or soft findings on moderate-trust app */
        ELEVATED,
        /** Minor concerns only — soft findings on high-trust app */
        LOW,
        /** No actionable findings */
        NOMINAL
    }

    // ──────────────────────────────────────────────────────────
    //  Evaluation logic
    // ──────────────────────────────────────────────────────────

    /**
     * Produce a verdict by combining trust evidence with raw findings.
     */
    fun evaluate(
        packageName: String,
        trustEvidence: TrustEvidenceEngine.TrustEvidence,
        rawFindings: List<RawFinding>,
        isSystemApp: Boolean
    ): AppVerdict {
        val adjustedFindings = rawFindings.map { finding ->
            adjustFinding(finding, trustEvidence)
        }

        // Calculate raw risk score from findings (0-100)
        val riskScore = calculateRiskScore(rawFindings)

        // Determine effective risk
        val hasHardFindings = adjustedFindings.any {
            it.hardness == FindingHardness.HARD && it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score
        }
        val maxAdjustedSeverity = adjustedFindings.maxOfOrNull { it.adjustedSeverity.score } ?: 0

        val effectiveRisk = when {
            hasHardFindings -> EffectiveRisk.CRITICAL
            trustEvidence.trustLevel == TrustEvidenceEngine.TrustLevel.ANOMALOUS -> EffectiveRisk.CRITICAL
            maxAdjustedSeverity >= AppSecurityScanner.RiskLevel.HIGH.score && trustEvidence.trustScore < 40 -> EffectiveRisk.CRITICAL
            maxAdjustedSeverity >= AppSecurityScanner.RiskLevel.MEDIUM.score -> EffectiveRisk.ELEVATED
            maxAdjustedSeverity >= AppSecurityScanner.RiskLevel.LOW.score -> EffectiveRisk.LOW
            else -> EffectiveRisk.NOMINAL
        }

        // System apps: show in main list only on strong anomalies
        val shouldShowInMainList = if (isSystemApp) {
            hasHardFindings || effectiveRisk == EffectiveRisk.CRITICAL
        } else {
            effectiveRisk != EffectiveRisk.NOMINAL
        }

        val (label, description) = generateVerdictText(effectiveRisk, trustEvidence, isSystemApp, adjustedFindings)

        return AppVerdict(
            packageName = packageName,
            trustScore = trustEvidence.trustScore,
            riskScore = riskScore,
            effectiveRisk = effectiveRisk,
            verdictLabel = label,
            verdictDescription = description,
            shouldShowInMainList = shouldShowInMainList,
            isSystemComponent = isSystemApp && trustEvidence.systemAppInfo.isSystemApp,
            adjustedFindings = adjustedFindings
        )
    }

    /**
     * Adjust a single finding based on trust evidence.
     * HARD findings are never downgraded. SOFT findings may be.
     */
    private fun adjustFinding(
        finding: RawFinding,
        trust: TrustEvidenceEngine.TrustEvidence
    ): AdjustedFinding {
        val hardness = finding.type.hardness

        // HARD findings: never downgrade
        if (hardness == FindingHardness.HARD) {
            return AdjustedFinding(
                findingType = finding.type,
                originalSeverity = finding.severity,
                adjustedSeverity = finding.severity,
                hardness = FindingHardness.HARD,
                wasDowngraded = false,
                title = finding.title
            )
        }

        // SOFT findings: downgrade based on trust score
        val adjustedSeverity = when {
            trust.trustScore >= 70 -> downgrade(finding.severity, 2) // HIGH trust → drop 2 levels
            trust.trustScore >= 40 -> downgrade(finding.severity, 1) // MODERATE trust → drop 1 level
            else -> finding.severity // LOW trust → keep as-is
        }

        return AdjustedFinding(
            findingType = finding.type,
            originalSeverity = finding.severity,
            adjustedSeverity = adjustedSeverity,
            hardness = FindingHardness.SOFT,
            wasDowngraded = adjustedSeverity != finding.severity,
            title = finding.title
        )
    }

    private fun downgrade(severity: AppSecurityScanner.RiskLevel, levels: Int): AppSecurityScanner.RiskLevel {
        val allLevels = AppSecurityScanner.RiskLevel.entries.sortedByDescending { it.score }
        val currentIdx = allLevels.indexOf(severity)
        val newIdx = (currentIdx + levels).coerceAtMost(allLevels.lastIndex)
        return allLevels[newIdx]
    }

    private fun calculateRiskScore(findings: List<RawFinding>): Int {
        var score = 0
        for (finding in findings) {
            score += when (finding.severity) {
                AppSecurityScanner.RiskLevel.CRITICAL -> 30
                AppSecurityScanner.RiskLevel.HIGH -> 20
                AppSecurityScanner.RiskLevel.MEDIUM -> 10
                AppSecurityScanner.RiskLevel.LOW -> 5
                AppSecurityScanner.RiskLevel.NONE -> 0
            }
        }
        return score.coerceIn(0, 100)
    }

    private fun generateVerdictText(
        risk: EffectiveRisk,
        trust: TrustEvidenceEngine.TrustEvidence,
        isSystem: Boolean,
        findings: List<AdjustedFinding>
    ): Pair<String, String> {
        val prefix = if (isSystem) "Systémová komponenta" else "Aplikace"

        return when (risk) {
            EffectiveRisk.CRITICAL -> {
                val hardCount = findings.count { it.hardness == FindingHardness.HARD }
                if (hardCount > 0) {
                    "Vyžaduje pozornost" to "$prefix vykazuje neobvyklé chování, které nelze vysvětlit důvěrou"
                } else {
                    "Ke kontrole" to "$prefix má podezřelé chování při nízké úrovni důvěry"
                }
            }
            EffectiveRisk.ELEVATED -> {
                if (trust.trustScore >= 40) {
                    "Drobné nedostatky" to "$prefix od ověřeného vývojáře má drobné nedostatky"
                } else {
                    "Doporučujeme zkontrolovat" to "$prefix má nálezy, které stojí za kontrolu"
                }
            }
            EffectiveRisk.LOW -> {
                "V pořádku" to "$prefix nemá významné problémy"
            }
            EffectiveRisk.NOMINAL -> {
                "Bezpečná" to "$prefix splňuje bezpečnostní standardy"
            }
        }
    }

    // ──────────────────────────────────────────────────────────
    //  Input type for raw findings (before trust adjustment)
    // ──────────────────────────────────────────────────────────

    data class RawFinding(
        val type: FindingType,
        val severity: AppSecurityScanner.RiskLevel,
        val title: String,
        val description: String
    )
}
