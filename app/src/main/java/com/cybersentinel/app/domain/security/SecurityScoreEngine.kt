package com.cybersentinel.app.domain.security

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Security Score Engine - calculates overall device security score (0-100)
 */

/**
 * Action types for resolving security issues
 */
enum class ActionType {
    OPEN_SETTINGS,
    OPEN_PLAY_STORE,
    OPEN_URL,
    IN_APP,
    NONE
}

/**
 * Resolves the action for a security issue and launches the appropriate intent
 */
fun resolveAction(context: Context, issue: SecurityIssue) {
    when (issue.action) {
        is IssueAction.OpenSettings -> {
            val intent = Intent(issue.action.settingsAction).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            try {
                context.startActivity(intent)
            } catch (e: Exception) {
                // Fallback to main settings
                context.startActivity(Intent(Settings.ACTION_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                })
            }
        }
        is IssueAction.OpenPlayStore -> {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                data = Uri.parse("market://details?id=${issue.action.packageName}")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            try {
                context.startActivity(intent)
            } catch (e: Exception) {
                // Fallback to web Play Store
                context.startActivity(Intent(Intent.ACTION_VIEW).apply {
                    data = Uri.parse("https://play.google.com/store/apps/details?id=${issue.action.packageName}")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                })
            }
        }
        is IssueAction.OpenUrl -> {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                data = Uri.parse(issue.action.url)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            context.startActivity(intent)
        }
        is IssueAction.InAppAction -> {
            // Handle in-app actions - will be implemented by specific screens
        }
        IssueAction.None -> {
            // No action available
        }
    }
}

/**
 * Action that user can take to resolve an issue
 */
sealed class IssueAction {
    abstract val label: String
    abstract val actionType: ActionType
    
    data class OpenSettings(val settingsAction: String, override val label: String) : IssueAction() {
        override val actionType = ActionType.OPEN_SETTINGS
    }
    data class OpenPlayStore(val packageName: String, override val label: String) : IssueAction() {
        override val actionType = ActionType.OPEN_PLAY_STORE
    }
    data class OpenUrl(val url: String, override val label: String) : IssueAction() {
        override val actionType = ActionType.OPEN_URL
    }
    data class InAppAction(val actionId: String, override val label: String) : IssueAction() {
        override val actionType = ActionType.IN_APP
    }
    object None : IssueAction() {
        override val label = ""
        override val actionType = ActionType.NONE
    }
}

data class SecurityIssue(
    val id: String,
    val title: String,
    val description: String,
    val impact: String,                          // Why this matters (1 sentence)
    val severity: Severity,
    val category: Category,
    val action: IssueAction = IssueAction.None,  // What user can do
    val confidence: Confidence = Confidence.HIGH,
    val source: String? = null,                  // NVD, CIRCL, Device API, etc.
    val detectedAt: Long = System.currentTimeMillis(),
    val isPremiumOnly: Boolean = false
) {
    enum class Severity(val weight: Int, val label: String) {
        CRITICAL(25, "Kritické"),
        HIGH(15, "Vysoké"),
        MEDIUM(8, "Střední"),
        LOW(3, "Nízké"),
        INFO(0, "Info")
    }
    
    enum class Category(val label: String) {
        DEVICE("Zařízení"),
        APPS("Aplikace"),
        NETWORK("Síť"),
        ACCOUNTS("Účty"),
        PASSWORDS("Hesla")
    }
    
    enum class Confidence(val label: String) {
        HIGH("Vysoká"),
        MEDIUM("Střední"),
        LOW("Nízká")
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
