package com.cybersentinel.app.domain.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.time.LocalDate
import javax.inject.Inject
import javax.inject.Singleton

data class InstalledApp(
    val packageName: String,
    val appName: String,
    val versionName: String?,
    val versionCode: Long,
    val isSystemApp: Boolean
)

/**
 * Scans installed apps and checks for known vulnerabilities
 */
@Singleton
class InstalledAppsScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {
    
    fun getInstalledApps(includeSystem: Boolean = false): List<InstalledApp> {
        val pm = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
        
        return packages
            .filter { includeSystem || !isSystemApp(it) }
            .map { pkg ->
                InstalledApp(
                    packageName = pkg.packageName,
                    appName = pm.getApplicationLabel(pkg.applicationInfo ?: return@map null).toString(),
                    versionName = pkg.versionName,
                    versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        pkg.longVersionCode
                    } else {
                        @Suppress("DEPRECATION")
                        pkg.versionCode.toLong()
                    },
                    isSystemApp = isSystemApp(pkg)
                )
            }
            .filterNotNull()
            .sortedBy { it.appName.lowercase() }
    }
    
    private fun isSystemApp(pkg: PackageInfo): Boolean {
        return pkg.applicationInfo?.let {
            (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        } ?: false
    }
    
    /**
     * Check apps against known vulnerable packages
     * In production, this would query a real CVE database with CPE matching
     */
    fun findVulnerableApps(apps: List<InstalledApp>): List<AppVulnerability> {
        val vulnerabilities = mutableListOf<AppVulnerability>()
        
        // Known vulnerable package patterns (simplified for demo)
        // In production: match against NVD CPE data
        val knownVulnerable = mapOf(
            "com.android.chrome" to VulnCheck("Chrome < 120", "120.0"),
            "com.android.webview" to VulnCheck("WebView < 120", "120.0"),
            "com.whatsapp" to VulnCheck("WhatsApp < 2.24", "2.24"),
            "com.facebook.orca" to VulnCheck("Messenger < 400", "400.0")
        )
        
        for (app in apps) {
            knownVulnerable[app.packageName]?.let { check ->
                if (isVersionLower(app.versionName, check.minSafeVersion)) {
                    vulnerabilities.add(
                        AppVulnerability(
                            app = app,
                            cveId = null, // Would come from real CVE lookup
                            description = check.description,
                            recommendation = "Aktualizujte aplikaci na nejnovější verzi"
                        )
                    )
                }
            }
        }
        
        return vulnerabilities
    }
    
    private fun isVersionLower(current: String?, minSafe: String): Boolean {
        if (current == null) return false
        return try {
            val currentMajor = current.split(".").firstOrNull()?.toIntOrNull() ?: 0
            val safeMajor = minSafe.split(".").firstOrNull()?.toIntOrNull() ?: 0
            currentMajor < safeMajor
        } catch (e: Exception) {
            false
        }
    }
    
    private data class VulnCheck(val description: String, val minSafeVersion: String)
}

data class AppVulnerability(
    val app: InstalledApp,
    val cveId: String?,
    val description: String,
    val recommendation: String
)
