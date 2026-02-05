package com.cybersentinel.app.domain.security

import com.cybersentinel.app.data.local.AppBaselineDao
import com.cybersentinel.app.data.local.AppBaselineEntity
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Baseline Manager — persists and compares app state across scans.
 *
 * "Nejlepší detektor pro systémové komponenty je *změna proti minulému stavu*."
 *
 * First scan → creates baseline: package + cert digest + version.
 * Subsequent scans → compares and flags:
 *  - CERT_CHANGED: signing cert changed → CRITICAL (possible supply-chain attack)
 *  - NEW_SYSTEM_APP: new system component appeared → HIGH
 *  - VERSION_CHANGE_NO_OTA: version changed unexpectedly → MEDIUM
 *  - APP_REMOVED: previously seen app disappeared → INFO
 *
 * This dramatically reduces false positives for system apps because we only
 * alert on *changes*, not on static state that's been there since factory reset.
 */
@Singleton
class BaselineManager @Inject constructor(
    private val baselineDao: AppBaselineDao
) {

    // ──────────────────────────────────────────────────────────
    //  Data model
    // ──────────────────────────────────────────────────────────

    /**
     * Result of comparing an app against its stored baseline
     */
    data class BaselineComparison(
        val packageName: String,
        val status: BaselineStatus,
        val anomalies: List<BaselineAnomaly>,
        val isFirstScan: Boolean,
        val scanCount: Int
    )

    enum class BaselineStatus {
        /** First time seeing this app */
        NEW,
        /** App matches baseline — no changes */
        UNCHANGED,
        /** App has changes that need attention */
        CHANGED,
        /** App was previously seen but is now gone */
        REMOVED
    }

    data class BaselineAnomaly(
        val type: AnomalyType,
        val severity: AnomalySeverity,
        val description: String,
        val details: String? = null
    )

    enum class AnomalyType {
        /** Signing certificate changed — CRITICAL */
        CERT_CHANGED,
        /** New system app appeared (wasn't there before) */
        NEW_SYSTEM_APP,
        /** Version changed (might be normal update or suspicious) */
        VERSION_CHANGED,
        /** Installer changed (e.g., was Play Store, now sideloaded) */
        INSTALLER_CHANGED,
        /** App partition changed (e.g., moved from /data to /system — suspicious) */
        PARTITION_CHANGED
    }

    enum class AnomalySeverity {
        CRITICAL,  // Cert change
        HIGH,      // New system app
        MEDIUM,    // Version/installer change
        LOW        // Minor changes
    }

    // ──────────────────────────────────────────────────────────
    //  Public API
    // ──────────────────────────────────────────────────────────

    /**
     * Compare current app state against stored baseline.
     * Returns comparison result with any anomalies.
     */
    suspend fun compareWithBaseline(
        packageName: String,
        currentCertSha256: String,
        currentVersionCode: Long,
        currentVersionName: String?,
        isSystemApp: Boolean,
        installerPackage: String?,
        apkPath: String?
    ): BaselineComparison {
        val existing = baselineDao.getBaseline(packageName)

        if (existing == null) {
            // First time seeing this app
            val anomalies = mutableListOf<BaselineAnomaly>()
            
            // If it's a system app appearing for the first time AFTER first scan has been done,
            // that's suspicious (a new system component shouldn't just appear)
            val totalBaselines = baselineDao.getBaselineCount()
            if (isSystemApp && totalBaselines > 0) {
                anomalies.add(BaselineAnomaly(
                    type = AnomalyType.NEW_SYSTEM_APP,
                    severity = AnomalySeverity.HIGH,
                    description = "Nová systémová komponenta: $packageName",
                    details = "Tato systémová aplikace nebyla přítomna při předchozím skenování. " +
                            "Mohlo jít o OTA aktualizaci, nebo o neautorizovanou modifikaci systému."
                ))
            }

            return BaselineComparison(
                packageName = packageName,
                status = BaselineStatus.NEW,
                anomalies = anomalies,
                isFirstScan = totalBaselines == 0,
                scanCount = 0
            )
        }

        // Compare against stored baseline
        val anomalies = mutableListOf<BaselineAnomaly>()

        // 1. CRITICAL: Certificate changed
        if (existing.certSha256 != currentCertSha256) {
            anomalies.add(BaselineAnomaly(
                type = AnomalyType.CERT_CHANGED,
                severity = AnomalySeverity.CRITICAL,
                description = "Podpisový certifikát se změnil!",
                details = "Předchozí: ${existing.certSha256.take(16)}...\n" +
                        "Aktuální: ${currentCertSha256.take(16)}...\n" +
                        "To může znamenat přebalení aplikace třetí stranou."
            ))
        }

        // 2. Version changed
        if (existing.versionCode != currentVersionCode) {
            anomalies.add(BaselineAnomaly(
                type = AnomalyType.VERSION_CHANGED,
                severity = AnomalySeverity.LOW, // Normal updates are expected
                description = "Verze se změnila: ${existing.versionName ?: existing.versionCode} → ${currentVersionName ?: currentVersionCode}",
                details = null
            ))
        }

        // 3. Installer changed (suspicious)
        if (existing.installerPackage != null && installerPackage != null &&
            existing.installerPackage != installerPackage) {
            anomalies.add(BaselineAnomaly(
                type = AnomalyType.INSTALLER_CHANGED,
                severity = AnomalySeverity.MEDIUM,
                description = "Zdroj instalace se změnil",
                details = "Předchozí: ${existing.installerPackage}\nAktuální: $installerPackage"
            ))
        }

        // 4. Partition changed (suspicious — app moved between system/data)
        if (existing.apkPath != null && apkPath != null) {
            val oldPartition = getPartition(existing.apkPath)
            val newPartition = getPartition(apkPath)
            if (oldPartition != newPartition) {
                anomalies.add(BaselineAnomaly(
                    type = AnomalyType.PARTITION_CHANGED,
                    severity = AnomalySeverity.MEDIUM,
                    description = "Umístění aplikace se změnilo: $oldPartition → $newPartition",
                    details = "Předchozí: ${existing.apkPath}\nAktuální: $apkPath"
                ))
            }
        }

        val status = if (anomalies.isEmpty()) BaselineStatus.UNCHANGED else BaselineStatus.CHANGED

        return BaselineComparison(
            packageName = packageName,
            status = status,
            anomalies = anomalies,
            isFirstScan = false,
            scanCount = existing.scanCount
        )
    }

    /**
     * Update the baseline after a scan.
     * Call this AFTER comparing, so the next scan sees the latest state.
     */
    suspend fun updateBaseline(
        packageName: String,
        certSha256: String,
        versionCode: Long,
        versionName: String?,
        isSystemApp: Boolean,
        installerPackage: String?,
        apkPath: String?
    ) {
        val now = System.currentTimeMillis()
        val existing = baselineDao.getBaseline(packageName)

        val entity = if (existing != null) {
            existing.copy(
                certSha256 = certSha256,
                versionCode = versionCode,
                versionName = versionName,
                isSystemApp = isSystemApp,
                installerPackage = installerPackage,
                apkPath = apkPath,
                lastSeenAt = now,
                scanCount = existing.scanCount + 1,
                // Track cert changes
                lastCertChangeAt = if (existing.certSha256 != certSha256) now else existing.lastCertChangeAt,
                previousCertSha256 = if (existing.certSha256 != certSha256) existing.certSha256 else existing.previousCertSha256
            )
        } else {
            AppBaselineEntity(
                packageName = packageName,
                certSha256 = certSha256,
                versionCode = versionCode,
                versionName = versionName,
                isSystemApp = isSystemApp,
                installerPackage = installerPackage,
                apkPath = apkPath,
                firstSeenAt = now,
                lastSeenAt = now,
                scanCount = 1
            )
        }

        baselineDao.upsertBaseline(entity)
    }

    /**
     * Detect apps that were in the baseline but are no longer installed.
     */
    suspend fun findRemovedApps(currentPackages: List<String>): List<BaselineComparison> {
        return baselineDao.findRemovedApps(currentPackages).map { entity ->
            BaselineComparison(
                packageName = entity.packageName,
                status = BaselineStatus.REMOVED,
                anomalies = emptyList(),
                isFirstScan = false,
                scanCount = entity.scanCount
            )
        }
    }

    /**
     * Check if this is the very first scan (no baselines exist)
     */
    suspend fun isFirstScan(): Boolean {
        return baselineDao.getBaselineCount() == 0
    }

    private fun getPartition(path: String): String {
        return when {
            path.startsWith("/system/") -> "system"
            path.startsWith("/vendor/") -> "vendor"
            path.startsWith("/product/") -> "product"
            path.startsWith("/data/") -> "data"
            else -> "unknown"
        }
    }
}
