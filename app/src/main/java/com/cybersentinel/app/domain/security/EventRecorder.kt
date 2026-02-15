package com.cybersentinel.app.domain.security

import com.cybersentinel.app.data.local.SecurityEventDao
import com.cybersentinel.app.data.local.SecurityEventEntity
import com.cybersentinel.app.domain.security.BaselineManager.AnomalySeverity
import com.cybersentinel.app.domain.security.BaselineManager.AnomalyType
import com.cybersentinel.app.domain.security.BaselineManager.BaselineComparison
import com.cybersentinel.app.domain.security.SpecialAccessInspector.SpecialAccessSnapshot
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * EventRecorder — bridges scanner outputs to SecurityEventEntity persistence.
 *
 * The scanning pipeline produces old-model objects (SecurityIssue, AppVulnerability,
 * BaselineAnomaly, SpecialAccessSnapshot). This class converts them into
 * SecurityEventEntity rows and inserts them via [SecurityEventDao].
 *
 * Deduplication: uses deterministic IDs based on source+category+package so that
 * re-scanning the same state does not create duplicate rows.
 *
 * Sprint UI-2: 3/10 — incidents actually appear in the list.
 */
@Singleton
class EventRecorder @Inject constructor(
    private val securityEventDao: SecurityEventDao
) {

    // ══════════════════════════════════════════════════════════
    //  Device + App scan results (from DashboardViewModel)
    // ══════════════════════════════════════════════════════════

    /**
     * Persist device-level SecurityIssues (from DeviceSecurityAnalyzer)
     * and app-vulnerability SecurityIssues together.
     *
     * Maps old-model [SecurityIssue] → [SecurityEventEntity] using:
     *  - severity mapping: CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM→MEDIUM, etc.
     *  - source: DEVICE_ANALYZER for device issues, APP_SCANNER for app issues
     *  - eventType: derived from category
     */
    suspend fun recordScanResults(
        deviceIssues: List<SecurityIssue>,
        appIssues: List<SecurityIssue>
    ) {
        val now = System.currentTimeMillis()
        val expiry = now + EXPIRY_MS

        val deviceEntities = deviceIssues.map { issue ->
            SecurityEventEntity(
                id = deterministicId("device", issue.id),
                startTime = issue.detectedAt,
                endTime = null,
                source = SignalSource.DEVICE_ANALYZER.name,
                eventType = mapCategoryToEventType(issue.category).name,
                severity = mapSeverity(issue.severity).name,
                packageName = null,
                summary = issue.title,
                metadata = buildMetadata(
                    "description" to issue.description,
                    "impact" to issue.impact,
                    "confidence" to issue.confidence.name,
                    "source" to (issue.source ?: "")
                ),
                expiresAt = expiry
            )
        }

        val appEntities = appIssues.map { issue ->
            SecurityEventEntity(
                id = deterministicId("app", issue.id),
                startTime = issue.detectedAt,
                endTime = null,
                source = SignalSource.APP_SCANNER.name,
                eventType = EventType.SUSPICIOUS_UPDATE.name,
                severity = mapSeverity(issue.severity).name,
                packageName = extractPackage(issue.id),
                summary = issue.title,
                metadata = buildMetadata(
                    "description" to issue.description,
                    "impact" to issue.impact,
                    "confidence" to issue.confidence.name,
                    "source" to (issue.source ?: "")
                ),
                expiresAt = expiry
            )
        }

        val all = deviceEntities + appEntities
        if (all.isNotEmpty()) {
            securityEventDao.insertAll(all)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Baseline anomalies
    // ══════════════════════════════════════════════════════════

    /**
     * Persist baseline anomalies from [BaselineManager.compareWithBaseline].
     *
     * Each [BaselineAnomaly] inside a [BaselineComparison] becomes one event.
     * Dedup key: baseline + packageName + anomalyType.
     */
    suspend fun recordBaselineAnomalies(comparisons: List<BaselineComparison>) {
        val now = System.currentTimeMillis()
        val expiry = now + EXPIRY_MS

        val entities = comparisons.flatMap { comparison ->
            comparison.anomalies.map { anomaly ->
                SecurityEventEntity(
                    id = deterministicId(
                        "baseline",
                        "${comparison.packageName}_${anomaly.type.name}"
                    ),
                    startTime = now,
                    endTime = null,
                    source = SignalSource.BASELINE.name,
                    eventType = mapAnomalyToEventType(anomaly.type).name,
                    severity = mapAnomalySeverity(anomaly.severity).name,
                    packageName = comparison.packageName,
                    summary = anomaly.description,
                    metadata = buildMetadata(
                        "anomalyType" to anomaly.type.name,
                        "details" to anomaly.details,
                        "scanCount" to comparison.scanCount.toString(),
                        "isFirstScan" to comparison.isFirstScan.toString()
                    ),
                    expiresAt = expiry
                )
            }
        }

        if (entities.isNotEmpty()) {
            securityEventDao.insertAll(entities)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Special access changes
    // ══════════════════════════════════════════════════════════

    /**
     * Persist special-access snapshots that have at least one active flag.
     *
     * Only records apps that [SpecialAccessSnapshot.hasAnySpecialAccess].
     * The metadata carries all flag values for downstream detail rendering.
     */
    suspend fun recordSpecialAccess(snapshots: List<SpecialAccessSnapshot>) {
        val now = System.currentTimeMillis()
        val expiry = now + EXPIRY_MS

        val entities = snapshots
            .filter { it.hasAnySpecialAccess }
            .map { snap ->
                SecurityEventEntity(
                    id = deterministicId("special", snap.packageName),
                    startTime = now,
                    endTime = null,
                    source = SignalSource.SPECIAL_ACCESS.name,
                    eventType = EventType.SPECIAL_ACCESS_GRANT.name,
                    severity = SignalSeverity.MEDIUM.name,
                    packageName = snap.packageName,
                    summary = "Speciální přístupy: ${snap.activeLabels.joinToString(", ")}",
                    metadata = buildMetadata(
                        "accessibility" to snap.accessibilityEnabled.toString(),
                        "notificationListener" to snap.notificationListenerEnabled.toString(),
                        "deviceAdmin" to snap.deviceAdminEnabled.toString(),
                        "overlay" to snap.overlayEnabled.toString(),
                        "defaultSms" to snap.isDefaultSms.toString(),
                        "defaultDialer" to snap.isDefaultDialer.toString(),
                        "batteryOptIgnored" to snap.batteryOptimizationIgnored.toString(),
                        "activeCount" to snap.activeCount.toString()
                    ),
                    expiresAt = expiry
                )
            }

        if (entities.isNotEmpty()) {
            securityEventDao.insertAll(entities)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Cleanup
    // ══════════════════════════════════════════════════════════

    /** Remove events older than [EXPIRY_MS]. */
    suspend fun cleanupExpired() {
        securityEventDao.deleteExpired(System.currentTimeMillis())
    }

    // ══════════════════════════════════════════════════════════
    //  Internal mapping
    // ══════════════════════════════════════════════════════════

    internal fun mapSeverity(severity: SecurityIssue.Severity): SignalSeverity {
        return when (severity) {
            SecurityIssue.Severity.CRITICAL -> SignalSeverity.CRITICAL
            SecurityIssue.Severity.HIGH -> SignalSeverity.HIGH
            SecurityIssue.Severity.MEDIUM -> SignalSeverity.MEDIUM
            SecurityIssue.Severity.LOW -> SignalSeverity.LOW
            SecurityIssue.Severity.INFO -> SignalSeverity.INFO
        }
    }

    internal fun mapCategoryToEventType(category: SecurityIssue.Category): EventType {
        return when (category) {
            SecurityIssue.Category.DEVICE -> EventType.DEVICE_COMPROMISE
            SecurityIssue.Category.APPS -> EventType.SUSPICIOUS_UPDATE
            SecurityIssue.Category.NETWORK -> EventType.CONFIG_TAMPER
            SecurityIssue.Category.ACCOUNTS -> EventType.OTHER
            SecurityIssue.Category.PASSWORDS -> EventType.OTHER
        }
    }

    internal fun mapAnomalyToEventType(type: AnomalyType): EventType {
        return when (type) {
            AnomalyType.CERT_CHANGED -> EventType.SUSPICIOUS_UPDATE
            AnomalyType.VERSION_ROLLBACK -> EventType.SUSPICIOUS_UPDATE
            AnomalyType.INSTALLER_CHANGED -> EventType.SUSPICIOUS_INSTALL
            AnomalyType.HIGH_RISK_PERMISSION_ADDED -> EventType.CAPABILITY_ESCALATION
            AnomalyType.EXPORTED_SURFACE_INCREASED -> EventType.CAPABILITY_ESCALATION
            AnomalyType.NEW_SYSTEM_APP -> EventType.SUSPICIOUS_INSTALL
            AnomalyType.VERSION_CHANGED -> EventType.OTHER
            AnomalyType.PARTITION_CHANGED -> EventType.DEVICE_COMPROMISE
            AnomalyType.PERMISSION_SET_CHANGED -> EventType.CAPABILITY_ESCALATION
        }
    }

    internal fun mapAnomalySeverity(severity: AnomalySeverity): SignalSeverity {
        return when (severity) {
            AnomalySeverity.CRITICAL -> SignalSeverity.CRITICAL
            AnomalySeverity.HIGH -> SignalSeverity.HIGH
            AnomalySeverity.MEDIUM -> SignalSeverity.MEDIUM
            AnomalySeverity.LOW -> SignalSeverity.LOW
        }
    }

    /**
     * Deterministic ID so re-scanning the same state = REPLACE, not duplicate.
     * Uses prefix + source-specific key, hashed to UUID-length.
     */
    internal fun deterministicId(prefix: String, key: String): String {
        return UUID.nameUUIDFromBytes("$prefix:$key".toByteArray()).toString()
    }

    /**
     * Extract package name from issue IDs like "app_vuln_com.example.app".
     */
    private fun extractPackage(issueId: String): String? {
        val prefix = "app_vuln_"
        return if (issueId.startsWith(prefix)) issueId.removePrefix(prefix) else null
    }

    /**
     * Build a simple JSON-ish metadata string from key-value pairs.
     * Filters out blank values. Format: {"key":"value","key2":"value2"}
     */
    internal fun buildMetadata(vararg pairs: Pair<String, String?>): String? {
        val filtered = pairs.filter { !it.second.isNullOrBlank() }
        if (filtered.isEmpty()) return null
        return filtered.joinToString(",", "{", "}") { (k, v) ->
            "\"$k\":\"${v.orEmpty()}\""
        }
    }

    companion object {
        /** Events auto-expire after 30 days. */
        const val EXPIRY_MS = 30L * 24 * 60 * 60 * 1000
    }
}
