package com.cybersentinel.app.domain.security

import com.cybersentinel.app.data.local.AppBaselineDao
import com.cybersentinel.app.data.local.AppBaselineEntity
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Baseline Manager — persists and compares app state across scans.
 *
 * "Nejlepší detektor pro systémové komponenty je *změna proti minulému stavu*."
 *
 * First scan → creates baseline: package + cert digest + version + permission hash + exported surface.
 * Subsequent scans → compares and flags:
 *  - CERT_CHANGED: signing cert changed → CRITICAL (possible supply-chain attack)
 *  - NEW_SYSTEM_APP: new system component appeared → HIGH
 *  - HIGH_RISK_PERMISSION_ADDED: SMS/Accessibility/DeviceAdmin/VPN added → HIGH
 *  - EXPORTED_SURFACE_INCREASED: more unprotected components → MEDIUM
 *  - INSTALLER_CHANGED: installer changed → MEDIUM
 *  - PARTITION_CHANGED: app moved between partitions → MEDIUM
 *  - PERMISSION_SET_CHANGED: permissions changed → LOW
 *  - VERSION_CHANGED: version changed (normal) → LOW
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
        PARTITION_CHANGED,
        /** Permission set changed — new permissions added */
        PERMISSION_SET_CHANGED,
        /** High-risk permission added (SMS, Accessibility, DeviceAdmin, VPN) */
        HIGH_RISK_PERMISSION_ADDED,
        /** Exported attack surface increased (more unprotected components) */
        EXPORTED_SURFACE_INCREASED,
        /** Version code decreased — possible downgrade attack */
        VERSION_ROLLBACK
    }

    enum class AnomalySeverity {
        CRITICAL,  // Cert change
        HIGH,      // New system app, high-risk permission added
        MEDIUM,    // Version/installer change, surface increase
        LOW        // Minor changes, permission set change
    }

    /**
     * Current exported surface snapshot — used for baseline comparison
     */
    data class ExportedSurface(
        val exportedActivityCount: Int = 0,
        val exportedServiceCount: Int = 0,
        val exportedReceiverCount: Int = 0,
        val exportedProviderCount: Int = 0,
        val unprotectedExportedCount: Int = 0
    )

    // ──────────────────────────────────────────────────────────
    //  High-risk permission set (changes to these are always flagged)
    // ──────────────────────────────────────────────────────────

    companion object {
        /** Permissions that are genuinely alarming when added between scans */
        val HIGH_RISK_PERMISSIONS = setOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_VPN_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Public API
    // ──────────────────────────────────────────────────────────

    /**
     * Compare current app state against stored baseline.
     * Now includes permission delta and exported surface delta.
     *
     * ## Baseline initialization semantics
     *
     * **First scan** (`scanCount == 0`, `isFirstScan == true`):
     *   The function creates the baseline entry. No anomalies are generated
     *   except [AnomalyType.NEW_SYSTEM_APP] when this is a system app and
     *   other baselines already exist (i.e. the app appeared between scans).
     *
     * **Subsequent scans** (`scanCount > 0`):
     *   The function compares the current state against the stored baseline.
     *   Anomalies (cert change, version rollback, installer switch, etc.)
     *   are only detectable from the second scan onwards.
     *
     * **Security during first scan:**
     *   The baseline cannot yet detect *change-based* anomalies. However,
     *   the other two scan axes provide coverage:
     *   - **Identity axis** ([TrustEvidenceEngine]): cert whitelist matching,
     *     signer domain classification, platform signature verification
     *   - **Capability axis** ([TrustRiskModel]): partition anomaly detection,
     *     privilege analysis, category-based permission whitelisting
     *
     *   Together these ensure that even on the very first scan, a compromised
     *   system component would be flagged by cert mismatch or partition anomaly
     *   rather than relying on baseline drift detection.
     */
    suspend fun compareWithBaseline(
        packageName: String,
        currentCertSha256: String,
        currentVersionCode: Long,
        currentVersionName: String?,
        isSystemApp: Boolean,
        installerPackage: String?,
        apkPath: String?,
        currentPermissions: List<String> = emptyList(),
        currentHighRiskPermissions: List<String> = emptyList(),
        currentExportedSurface: ExportedSurface = ExportedSurface()
    ): BaselineComparison {
        val existing = baselineDao.getBaseline(packageName)

        if (existing == null) {
            // First time seeing this app
            val anomalies = mutableListOf<BaselineAnomaly>()
            
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

        // 2. Version changed — check for rollback (downgrade attack)
        if (existing.versionCode != currentVersionCode) {
            if (currentVersionCode < existing.versionCode) {
                // VERSION ROLLBACK — downgrade is highly suspicious
                anomalies.add(BaselineAnomaly(
                    type = AnomalyType.VERSION_ROLLBACK,
                    severity = AnomalySeverity.HIGH,
                    description = "Verze aplikace byla snížena: ${existing.versionName ?: existing.versionCode} → ${currentVersionName ?: currentVersionCode}",
                    details = "versionCode: ${existing.versionCode} → $currentVersionCode\n" +
                            "Downgrade může znamenat supply-chain útok nebo instalaci starší, " +
                            "zranitelné verze aplikace."
                ))
            } else {
                anomalies.add(BaselineAnomaly(
                    type = AnomalyType.VERSION_CHANGED,
                    severity = AnomalySeverity.LOW,
                    description = "Verze se změnila: ${existing.versionName ?: existing.versionCode} → ${currentVersionName ?: currentVersionCode}",
                    details = null
                ))
            }
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

        // 4. Partition changed
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

        // 5. Permission set changed
        val currentPermHash = hashPermissionSet(currentPermissions)
        if (existing.permissionSetHash != null && existing.permissionSetHash.isNotEmpty()
            && currentPermHash.isNotEmpty() && currentPermHash != existing.permissionSetHash) {
            anomalies.add(BaselineAnomaly(
                type = AnomalyType.PERMISSION_SET_CHANGED,
                severity = AnomalySeverity.LOW,
                description = "Sada oprávnění se změnila",
                details = "Aplikace nyní požaduje jiná oprávnění než při posledním skenování."
            ))
        }

        // 6. HIGH-RISK permission added (key delta detection)
        if (existing.highRiskPermissions != null) {
            val previousHighRisk = existing.highRiskPermissions.split(",")
                .filter { it.isNotBlank() }.toSet()
            val currentHighRisk = currentHighRiskPermissions.toSet()
            val newlyAdded = currentHighRisk - previousHighRisk
            
            if (newlyAdded.isNotEmpty()) {
                val addedNames = newlyAdded.map { it.substringAfterLast(".") }
                anomalies.add(BaselineAnomaly(
                    type = AnomalyType.HIGH_RISK_PERMISSION_ADDED,
                    severity = AnomalySeverity.HIGH,
                    description = "Přidána vysoce riziková oprávnění: ${addedNames.joinToString(", ")}",
                    details = "Nová oprávnění: ${newlyAdded.joinToString("\n")}\n" +
                            "Předchozí: ${previousHighRisk.joinToString(", ") { it.substringAfterLast(".") }}"
                ))
            }
        }

        // 7. Exported surface increased — RELATIVE delta
        // +1 on 80-component app = nothing, +10 on 0-component app = big signal
        val oldUnprotected = existing.unprotectedExportedCount
        val newUnprotected = currentExportedSurface.unprotectedExportedCount
        val surfaceDelta = newUnprotected - oldUnprotected
        if (surfaceDelta > 0) {
            val severity = when {
                // From 0 to anything — new attack surface where there was none
                oldUnprotected == 0 && newUnprotected >= 2 -> AnomalySeverity.HIGH
                // Large relative increase (50%+) or absolute jump of 5+
                oldUnprotected > 0 && (surfaceDelta.toFloat() / oldUnprotected >= 0.5f || surfaceDelta >= 5) ->
                    AnomalySeverity.MEDIUM
                // Small relative increase on large surface — barely notable
                else -> AnomalySeverity.LOW
            }
            anomalies.add(BaselineAnomaly(
                type = AnomalyType.EXPORTED_SURFACE_INCREASED,
                severity = severity,
                description = "Útočná plocha se zvětšila o $surfaceDelta nechráněných komponent",
                details = "Předchozí: $oldUnprotected nechráněných\n" +
                        "Aktuální: $newUnprotected nechráněných\n" +
                        "Relativní změna: ${if (oldUnprotected > 0) "${(surfaceDelta * 100 / oldUnprotected)}%" else "z 0"}"
            ))
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
     * Now persists permission hash and exported surface.
     */
    suspend fun updateBaseline(
        packageName: String,
        certSha256: String,
        versionCode: Long,
        versionName: String?,
        isSystemApp: Boolean,
        installerPackage: String?,
        apkPath: String?,
        permissions: List<String> = emptyList(),
        highRiskPermissions: List<String> = emptyList(),
        exportedSurface: ExportedSurface = ExportedSurface()
    ) {
        val now = System.currentTimeMillis()
        val existing = baselineDao.getBaseline(packageName)
        val permHash = hashPermissionSet(permissions)

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
                previousCertSha256 = if (existing.certSha256 != certSha256) existing.certSha256 else existing.previousCertSha256,
                // Permission baseline
                permissionSetHash = permHash,
                highRiskPermissions = highRiskPermissions.joinToString(","),
                // Exported surface baseline
                exportedActivityCount = exportedSurface.exportedActivityCount,
                exportedServiceCount = exportedSurface.exportedServiceCount,
                exportedReceiverCount = exportedSurface.exportedReceiverCount,
                exportedProviderCount = exportedSurface.exportedProviderCount,
                unprotectedExportedCount = exportedSurface.unprotectedExportedCount
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
                scanCount = 1,
                permissionSetHash = permHash,
                highRiskPermissions = highRiskPermissions.joinToString(","),
                exportedActivityCount = exportedSurface.exportedActivityCount,
                exportedServiceCount = exportedSurface.exportedServiceCount,
                exportedReceiverCount = exportedSurface.exportedReceiverCount,
                exportedProviderCount = exportedSurface.exportedProviderCount,
                unprotectedExportedCount = exportedSurface.unprotectedExportedCount
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

    /**
     * Check if system apps have been scanned before.
     * Returns true if there's at least one system app in the baseline.
     * This is used to distinguish "system app new because user toggled system visibility"
     * from "system app genuinely appeared (e.g., OTA update)".
     */
    suspend fun hasSystemAppsInBaseline(): Boolean {
        return baselineDao.getSystemAppBaselineCount() > 0
    }

    // ──────────────────────────────────────────────────────────
    //  Utility
    // ──────────────────────────────────────────────────────────

    /**
     * Compute a stable hash of the permission set (sorted, then SHA-256).
     * Used to detect permission delta without storing the full list.
     */
    private fun hashPermissionSet(permissions: List<String>): String {
        if (permissions.isEmpty()) return ""
        val sorted = permissions.sorted().joinToString(",")
        return MessageDigest.getInstance("SHA-256")
            .digest(sorted.toByteArray())
            .joinToString("") { "%02X".format(it) }
            .take(32) // 32 hex chars = 128 bits, sufficient for delta detection
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
