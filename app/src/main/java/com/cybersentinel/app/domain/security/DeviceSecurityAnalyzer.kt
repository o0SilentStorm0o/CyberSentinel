package com.cybersentinel.app.domain.security

import android.os.Build
import javax.inject.Inject
import javax.inject.Singleton
import java.time.LocalDate
import java.time.temporal.ChronoUnit

/**
 * Analyzes device security posture
 */
@Singleton
class DeviceSecurityAnalyzer @Inject constructor() {
    
    fun analyzeDevice(): List<SecurityIssue> {
        val issues = mutableListOf<SecurityIssue>()
        
        // Check Android version
        val androidVersion = Build.VERSION.SDK_INT
        if (androidVersion < Build.VERSION_CODES.Q) { // Android 10
            issues.add(
                SecurityIssue(
                    id = "device_old_android",
                    title = "Zastaralá verze Androidu",
                    description = "Android ${Build.VERSION.RELEASE} již nedostává bezpečnostní aktualizace",
                    severity = SecurityIssue.Severity.HIGH,
                    category = SecurityIssue.Category.DEVICE,
                    actionLabel = "Více informací"
                )
            )
        } else if (androidVersion < Build.VERSION_CODES.S) { // Android 12
            issues.add(
                SecurityIssue(
                    id = "device_aging_android",
                    title = "Starší verze Androidu",
                    description = "Android ${Build.VERSION.RELEASE} má omezené bezpečnostní aktualizace",
                    severity = SecurityIssue.Severity.MEDIUM,
                    category = SecurityIssue.Category.DEVICE
                )
            )
        }
        
        // Check security patch level
        val patchDate = parseSecurityPatch(Build.VERSION.SECURITY_PATCH)
        if (patchDate != null) {
            val monthsOld = ChronoUnit.MONTHS.between(patchDate, LocalDate.now())
            when {
                monthsOld > 12 -> issues.add(
                    SecurityIssue(
                        id = "device_patch_critical",
                        title = "Kriticky zastaralé zabezpečení",
                        description = "Bezpečnostní záplata je stará více než rok",
                        severity = SecurityIssue.Severity.CRITICAL,
                        category = SecurityIssue.Category.DEVICE,
                        actionLabel = "Zkontrolovat aktualizace"
                    )
                )
                monthsOld > 6 -> issues.add(
                    SecurityIssue(
                        id = "device_patch_old",
                        title = "Zastaralé bezpečnostní záplaty",
                        description = "Bezpečnostní záplata je stará $monthsOld měsíců",
                        severity = SecurityIssue.Severity.HIGH,
                        category = SecurityIssue.Category.DEVICE,
                        actionLabel = "Zkontrolovat aktualizace"
                    )
                )
                monthsOld > 3 -> issues.add(
                    SecurityIssue(
                        id = "device_patch_aging",
                        title = "Starší bezpečnostní záplaty",
                        description = "Bezpečnostní záplata je stará $monthsOld měsíců",
                        severity = SecurityIssue.Severity.MEDIUM,
                        category = SecurityIssue.Category.DEVICE
                    )
                )
            }
        }
        
        // Check if device is rooted (basic check)
        if (isRooted()) {
            issues.add(
                SecurityIssue(
                    id = "device_rooted",
                    title = "Zařízení je rootované",
                    description = "Rootovaná zařízení jsou náchylnější k malware",
                    severity = SecurityIssue.Severity.HIGH,
                    category = SecurityIssue.Category.DEVICE
                )
            )
        }
        
        return issues
    }
    
    private fun parseSecurityPatch(patch: String?): LocalDate? {
        return try {
            patch?.let { LocalDate.parse(it) }
        } catch (e: Exception) {
            null
        }
    }
    
    private fun isRooted(): Boolean {
        val paths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su"
        )
        return paths.any { java.io.File(it).exists() }
    }
}
