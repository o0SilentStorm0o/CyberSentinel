package com.cybersentinel.app.domain.security

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Security Score Engine - calculates overall device security score (0-100)
 */

data class SecurityIssue(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val category: Category,
    val actionLabel: String? = null
) {
    enum class Severity(val weight: Int) {
        CRITICAL(25),
        HIGH(15),
        MEDIUM(8),
        LOW(3),
        INFO(0)
    }
    
    enum class Category {
        DEVICE,
        APPS,
        NETWORK,
        ACCOUNTS,
        PASSWORDS
    }
}

data class SecurityScore(
    val score: Int,                          // 0-100
    val level: ScoreLevel,
    val issues: List<SecurityIssue>,
    val breakdown: ScoreBreakdown
)

data class ScoreBreakdown(
    val device: Int,      // 0-25
    val apps: Int,        // 0-25
    val network: Int,     // 0-25
    val accounts: Int     // 0-25
)

enum class ScoreLevel(val label: String, val emoji: String) {
    CRITICAL("Kritické", "🔴"),
    AT_RISK("Ohrožené", "🟠"),
    FAIR("Uspokojivé", "🟡"),
    GOOD("Dobré", "🟢"),
    EXCELLENT("Výborné", "💚")
}

@Singleton
class SecurityScoreEngine @Inject constructor() {
    
    fun calculateScore(
        deviceIssues: List<SecurityIssue>,
        appIssues: List<SecurityIssue>,
        networkIssues: List<SecurityIssue>,
        accountIssues: List<SecurityIssue>
    ): SecurityScore {
        val allIssues = deviceIssues + appIssues + networkIssues + accountIssues
        
        // Calculate penalties per category (max 25 points each)
        val devicePenalty = calculateCategoryPenalty(deviceIssues)
        val appsPenalty = calculateCategoryPenalty(appIssues)
        val networkPenalty = calculateCategoryPenalty(networkIssues)
        val accountsPenalty = calculateCategoryPenalty(accountIssues)
        
        val breakdown = ScoreBreakdown(
            device = 25 - devicePenalty,
            apps = 25 - appsPenalty,
            network = 25 - networkPenalty,
            accounts = 25 - accountsPenalty
        )
        
        val totalScore = (breakdown.device + breakdown.apps + breakdown.network + breakdown.accounts)
            .coerceIn(0, 100)
        
        val level = when {
            totalScore >= 90 -> ScoreLevel.EXCELLENT
            totalScore >= 75 -> ScoreLevel.GOOD
            totalScore >= 55 -> ScoreLevel.FAIR
            totalScore >= 35 -> ScoreLevel.AT_RISK
            else -> ScoreLevel.CRITICAL
        }
        
        return SecurityScore(
            score = totalScore,
            level = level,
            issues = allIssues.sortedByDescending { it.severity.weight },
            breakdown = breakdown
        )
    }
    
    private fun calculateCategoryPenalty(issues: List<SecurityIssue>): Int {
        return issues.sumOf { it.severity.weight }.coerceAtMost(25)
    }
}
