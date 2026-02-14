package com.cybersentinel.app.data.local

import androidx.room.*

/**
 * Room entity for persisting config baseline snapshots.
 * Stores the last known config state for delta detection between scans.
 * Only one row — the latest snapshot — is kept.
 */
@Entity(tableName = "config_baseline")
data class ConfigBaselineEntity(
    @PrimaryKey
    val id: Int = 1, // Singleton — only one config baseline per device
    val timestamp: Long,
    /** Comma-separated SHA-256 fingerprints of user CA certs */
    val userCaCertFingerprints: String? = null,
    val userCaCertCount: Int = 0,
    val privateDnsMode: String? = null,
    val privateDnsHostname: String? = null,
    val vpnActive: Boolean = false,
    val globalProxyConfigured: Boolean = false,
    val proxyHost: String? = null,
    /** Comma-separated package names with enabled accessibility services */
    val enabledAccessibilityServices: String? = null,
    /** Comma-separated package names with enabled notification listeners */
    val enabledNotificationListeners: String? = null,
    val defaultSmsApp: String? = null,
    val defaultDialerApp: String? = null,
    val developerOptionsEnabled: Boolean = false,
    val usbDebuggingEnabled: Boolean = false,
    val installFromUnknownSourcesEnabled: Boolean = false,
    /** SHA-256 hash of the entire config snapshot for quick change detection */
    val configHash: String? = null
)

@Dao
interface ConfigBaselineDao {
    @Query("SELECT * FROM config_baseline WHERE id = 1")
    suspend fun get(): ConfigBaselineEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(entity: ConfigBaselineEntity)

    @Query("DELETE FROM config_baseline")
    suspend fun clear()
}
