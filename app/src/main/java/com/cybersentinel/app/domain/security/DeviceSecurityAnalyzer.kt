package com.cybersentinel.app.domain.security

import android.os.Build
import android.provider.Settings
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
                    impact = "Útočníci mohou využít známé zranitelnosti, které už nebudou opraveny.",
                    severity = SecurityIssue.Severity.HIGH,
                    category = SecurityIssue.Category.DEVICE,
                    action = IssueAction.OpenSettings(
                        settingsAction = Settings.ACTION_DEVICE_INFO_SETTINGS,
                        label = "Zkontrolovat verzi"
                    ),
                    source = "Device API",
                    confidence = SecurityIssue.Confidence.HIGH
                )
            )
        } else if (androidVersion < Build.VERSION_CODES.S) { // Android 12
            issues.add(
                SecurityIssue(
                    id = "device_aging_android",
                    title = "Starší verze Androidu",
                    description = "Android ${Build.VERSION.RELEASE} má omezené bezpečnostní aktualizace",
                    impact = "Některé nové bezpečnostní funkce nejsou dostupné.",
                    severity = SecurityIssue.Severity.MEDIUM,
                    category = SecurityIssue.Category.DEVICE,
                    action = IssueAction.OpenSettings(
                        settingsAction = Settings.ACTION_DEVICE_INFO_SETTINGS,
                        label = "Informace o zařízení"
                    ),
                    source = "Device API",
                    confidence = SecurityIssue.Confidence.HIGH
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
                        description = "Bezpečnostní záplata je stará více než rok (${Build.VERSION.SECURITY_PATCH})",
                        impact = "Vaše zařízení je zranitelné vůči desítkám známých útoků.",
                        severity = SecurityIssue.Severity.CRITICAL,
                        category = SecurityIssue.Category.DEVICE,
                        action = IssueAction.OpenSettings(
                            settingsAction = Settings.ACTION_SETTINGS,
                            label = "Zkontrolovat aktualizace"
                        ),
                        source = "Device API",
                        confidence = SecurityIssue.Confidence.HIGH
                    )
                )
                monthsOld > 6 -> issues.add(
                    SecurityIssue(
                        id = "device_patch_old",
                        title = "Zastaralé bezpečnostní záplaty",
                        description = "Bezpečnostní záplata je stará $monthsOld měsíců",
                        impact = "Chybí vám opravy pro nedávno objevené zranitelnosti.",
                        severity = SecurityIssue.Severity.HIGH,
                        category = SecurityIssue.Category.DEVICE,
                        action = IssueAction.OpenSettings(
                            settingsAction = Settings.ACTION_SETTINGS,
                            label = "Zkontrolovat aktualizace"
                        ),
                        source = "Device API",
                        confidence = SecurityIssue.Confidence.HIGH
                    )
                )
                monthsOld > 3 -> issues.add(
                    SecurityIssue(
                        id = "device_patch_aging",
                        title = "Starší bezpečnostní záplaty",
                        description = "Bezpečnostní záplata je stará $monthsOld měsíců",
                        impact = "Doporučujeme aktualizovat při nejbližší příležitosti.",
                        severity = SecurityIssue.Severity.MEDIUM,
                        category = SecurityIssue.Category.DEVICE,
                        action = IssueAction.OpenSettings(
                            settingsAction = Settings.ACTION_SETTINGS,
                            label = "Zkontrolovat aktualizace"
                        ),
                        source = "Device API",
                        confidence = SecurityIssue.Confidence.HIGH
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
                    description = "Detekován root přístup na zařízení",
                    impact = "Škodlivé aplikace mohou získat plnou kontrolu nad zařízením.",
                    severity = SecurityIssue.Severity.HIGH,
                    category = SecurityIssue.Category.DEVICE,
                    action = IssueAction.OpenUrl(
                        url = "https://support.google.com/android/answer/10459462",
                        label = "Více informací"
                    ),
                    source = "Device API",
                    confidence = SecurityIssue.Confidence.MEDIUM
                )
            )
        }
        
        // Check screen lock
        // Note: In production, use KeyguardManager.isDeviceSecure()
        
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
