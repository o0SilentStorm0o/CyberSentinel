package com.cybersentinel.app.domain.security

/**
 * ScanDiagnostics — debug-only report for beta-testing and model validation.
 *
 * Provides per-verdict counts, top finding triggers, and unknown category/installer percentages.
 * This data is intended for internal logging and developer diagnostics, NOT for end-user display.
 */
data class ScanDiagnostics(
    val totalApps: Int,
    val perVerdictCounts: Map<TrustRiskModel.EffectiveRisk, Int>,
    val topTriggers: List<TriggerSummary>,
    val unknownInstallerPercent: Float,
    val unknownCategoryPercent: Float,
    val comboMatchCounts: Map<String, Int>,
    val hardFindingCount: Int,
    val averageTrustScore: Float
) {
    data class TriggerSummary(
        val findingType: TrustRiskModel.FindingType,
        val count: Int
    )

    fun toDebugString(): String = buildString {
        appendLine("═══ CyberSentinel Scan Diagnostics ═══")
        appendLine("Total apps scanned: $totalApps")
        appendLine()
        appendLine("── Per-verdict breakdown ──")
        TrustRiskModel.EffectiveRisk.entries.forEach { risk ->
            val count = perVerdictCounts[risk] ?: 0
            val pct = if (totalApps > 0) "%.1f%%".format(count * 100f / totalApps) else "0%"
            appendLine("  ${risk.emoji} ${risk.label}: $count ($pct)")
        }
        appendLine()
        appendLine("── Top triggers ──")
        topTriggers.take(10).forEach { (type, count) ->
            appendLine("  $type: $count")
        }
        appendLine()
        appendLine("── Model health ──")
        appendLine("  Hard findings: $hardFindingCount")
        appendLine("  Unknown installer: ${"%.1f%%".format(unknownInstallerPercent)}")
        appendLine("  Unknown category: ${"%.1f%%".format(unknownCategoryPercent)}")
        appendLine("  Avg trust score: ${"%.0f".format(averageTrustScore)}")
        if (comboMatchCounts.isNotEmpty()) {
            appendLine()
            appendLine("── Combo matches ──")
            comboMatchCounts.entries.sortedByDescending { it.value }.forEach { (name, count) ->
                appendLine("  $name: $count")
            }
        }
        appendLine("═══════════════════════════════════════")
    }

    companion object {
        /**
         * Build diagnostics from a list of scan verdicts.
         */
        fun fromVerdicts(
            verdicts: List<TrustRiskModel.AppVerdict>,
            categories: Map<String, AppCategoryDetector.AppCategory> = emptyMap(),
            installerTypes: Map<String, TrustEvidenceEngine.InstallerType> = emptyMap()
        ): ScanDiagnostics {
            val total = verdicts.size
            if (total == 0) return empty()

            // Per-verdict counts
            val perVerdict = verdicts.groupBy { it.effectiveRisk }
                .mapValues { it.value.size }

            // Top triggers — aggregate finding types across all verdicts
            val triggerCounts = mutableMapOf<TrustRiskModel.FindingType, Int>()
            verdicts.forEach { verdict ->
                verdict.adjustedFindings.forEach { f ->
                    triggerCounts[f.findingType] = (triggerCounts[f.findingType] ?: 0) + 1
                }
            }
            val topTriggers = triggerCounts.entries
                .sortedByDescending { it.value }
                .map { TriggerSummary(it.key, it.value) }

            // Combo match counts
            val comboCounts = mutableMapOf<String, Int>()
            verdicts.forEach { verdict ->
                verdict.matchedCombos.forEach { name ->
                    comboCounts[name] = (comboCounts[name] ?: 0) + 1
                }
            }

            // Hard finding count
            val hardCount = verdicts.sumOf { verdict ->
                verdict.adjustedFindings.count {
                    it.hardness == TrustRiskModel.FindingHardness.HARD &&
                    it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score
                }
            }

            // Unknown installer %
            val unknownInstallerCount = installerTypes.count {
                it.value == TrustEvidenceEngine.InstallerType.UNKNOWN
            }
            val unknownInstallerPct = if (total > 0) unknownInstallerCount * 100f / total else 0f

            // Unknown category %
            val unknownCategoryCount = categories.count {
                it.value == AppCategoryDetector.AppCategory.OTHER
            }
            val unknownCategoryPct = if (total > 0) unknownCategoryCount * 100f / total else 0f

            // Average trust score
            val avgTrust = verdicts.map { it.trustScore }.average().toFloat()

            return ScanDiagnostics(
                totalApps = total,
                perVerdictCounts = perVerdict,
                topTriggers = topTriggers,
                unknownInstallerPercent = unknownInstallerPct,
                unknownCategoryPercent = unknownCategoryPct,
                comboMatchCounts = comboCounts,
                hardFindingCount = hardCount,
                averageTrustScore = avgTrust
            )
        }

        fun empty() = ScanDiagnostics(
            totalApps = 0,
            perVerdictCounts = emptyMap(),
            topTriggers = emptyList(),
            unknownInstallerPercent = 0f,
            unknownCategoryPercent = 0f,
            comboMatchCounts = emptyMap(),
            hardFindingCount = 0,
            averageTrustScore = 0f
        )
    }
}
