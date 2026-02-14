package com.cybersentinel.app.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persisted baseline record for one app.
 * Used to detect changes between scans — the best false-positive killer for system apps.
 *
 * Key fields:
 *  - certSha256: signing certificate SHA-256 (detects re-signing)
 *  - versionCode / versionName: detect updates
 *  - isSystemApp: partition info
 *  - firstSeenAt / lastSeenAt: detect new appearances
 *  - permissionSetHash: sorted permission list hash for delta detection
 *  - exported component counts: attack surface delta tracking
 */
@Entity(tableName = "app_baseline")
data class AppBaselineEntity(
    @PrimaryKey
    val packageName: String,
    
    /** SHA-256 of the signing certificate */
    val certSha256: String,
    
    /** Version code at time of baseline */
    val versionCode: Long,
    
    /** Version name at time of baseline */
    val versionName: String?,
    
    /** Was this a system app when baselined? */
    val isSystemApp: Boolean,
    
    /** Installer package at baseline time */
    val installerPackage: String?,
    
    /** APK path (partition detection) */
    val apkPath: String?,
    
    /** First time this app was seen in a scan */
    val firstSeenAt: Long,
    
    /** Last time this app was seen in a scan */
    val lastSeenAt: Long,
    
    /** Last time the cert changed (0 = never changed) */
    val lastCertChangeAt: Long = 0,
    
    /** Previous cert if it changed */
    val previousCertSha256: String? = null,
    
    /** How many times we've scanned this app */
    val scanCount: Int = 1,
    
    // ── Permission baseline (v4) ──
    
    /** SHA-256 hash of sorted permission set — detects permission delta between scans */
    val permissionSetHash: String? = null,
    
    /** Comma-separated list of high-risk permissions (SMS/Accessibility/DeviceAdmin/VPN) at baseline */
    val highRiskPermissions: String? = null,
    
    // ── Exported surface baseline (v4) ──
    
    /** Count of exported activities */
    val exportedActivityCount: Int = 0,
    
    /** Count of exported services */
    val exportedServiceCount: Int = 0,
    
    /** Count of exported receivers */
    val exportedReceiverCount: Int = 0,
    
    /** Count of exported providers */
    val exportedProviderCount: Int = 0,
    
    /** Count of exported components without permission protection */
    val unprotectedExportedCount: Int = 0,

    // ── Time correlation fields (v5) ──

    /** Timestamp of last app update (versionCode change) */
    val lastUpdateAt: Long? = null,

    /** Timestamp of last installer change (e.g., Play Store → sideload) */
    val lastInstallerChangeAt: Long? = null,

    /** Timestamp of last high-risk permission addition */
    val lastHighRiskPermAddedAt: Long? = null,

    /** Timestamp of last special access enablement (accessibility, notif listener, etc.) */
    val lastSpecialAccessEnabledAt: Long? = null
)
