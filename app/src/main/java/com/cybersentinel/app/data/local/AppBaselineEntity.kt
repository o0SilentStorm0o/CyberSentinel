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
    val scanCount: Int = 1
)
