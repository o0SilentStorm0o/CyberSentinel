package com.cybersentinel.data.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "cybersentinel_preferences")

/**
 * Centrální preferences management pro CyberSentinel
 */
@Singleton
class AppPreferences @Inject constructor(
    private val context: Context
) {
    // Theme preferences
    private val THEME_KEY = booleanPreferencesKey("dark_theme")
    
    // Notification preferences
    private val NOTIFICATIONS_ENABLED_KEY = booleanPreferencesKey("notifications_enabled")
    private val CVE_NOTIFICATIONS_KEY = booleanPreferencesKey("cve_notifications")
    
    // CVE Monitor preferences
    private val AUTO_REFRESH_KEY = booleanPreferencesKey("auto_refresh")
    private val REFRESH_INTERVAL_KEY = intPreferencesKey("refresh_interval")
    private val LAST_CVE_SYNC_KEY = longPreferencesKey("last_cve_sync")
    
    // QR Scanner preferences
    private val QR_SENSITIVITY_KEY = intPreferencesKey("qr_sensitivity")
    private val SCAN_HISTORY_ENABLED_KEY = booleanPreferencesKey("scan_history_enabled")
    
    // Wi-Fi Auditor preferences
    private val WIFI_SCAN_INTERVAL_KEY = intPreferencesKey("wifi_scan_interval")
    private val WIFI_AUTO_SCAN_KEY = booleanPreferencesKey("wifi_auto_scan")
    
    // HIBP preferences
    private val HIBP_API_ENABLED_KEY = booleanPreferencesKey("hibp_api_enabled")
    private val PASSWORD_HISTORY_KEY = booleanPreferencesKey("password_history")
    
    // Advanced preferences
    private val CACHE_SIZE_KEY = intPreferencesKey("cache_size")
    private val DEBUG_MODE_KEY = booleanPreferencesKey("debug_mode")
    
    // Email monitoring & Premium
    private val MONITORED_EMAIL_KEY = stringPreferencesKey("monitored_email")
    private val IS_PREMIUM_KEY = booleanPreferencesKey("is_premium")
    
    // Theme Management
    val isDarkTheme: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[THEME_KEY] ?: false }
    
    suspend fun setDarkTheme(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[THEME_KEY] = enabled
        }
    }
    
    // Notification Management
    val notificationsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[NOTIFICATIONS_ENABLED_KEY] ?: true }
    
    suspend fun setNotificationsEnabled(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[NOTIFICATIONS_ENABLED_KEY] = enabled
        }
    }
    
    val cveNotifications: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[CVE_NOTIFICATIONS_KEY] ?: true }
    
    suspend fun setCveNotifications(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[CVE_NOTIFICATIONS_KEY] = enabled
        }
    }
    
    // CVE Monitor Management
    val autoRefresh: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[AUTO_REFRESH_KEY] ?: true }
    
    suspend fun setAutoRefresh(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[AUTO_REFRESH_KEY] = enabled
        }
    }
    
    val refreshInterval: Flow<Int> = context.dataStore.data
        .map { preferences -> preferences[REFRESH_INTERVAL_KEY] ?: 24 }
    
    suspend fun setRefreshInterval(hours: Int) {
        context.dataStore.edit { preferences ->
            preferences[REFRESH_INTERVAL_KEY] = hours
        }
    }
    
    val lastCveSync: Flow<Long> = context.dataStore.data
        .map { preferences -> preferences[LAST_CVE_SYNC_KEY] ?: 0L }
    
    suspend fun setLastCveSync(timestamp: Long) {
        context.dataStore.edit { preferences ->
            preferences[LAST_CVE_SYNC_KEY] = timestamp
        }
    }
    
    // QR Scanner Management
    val qrSensitivity: Flow<Int> = context.dataStore.data
        .map { preferences -> preferences[QR_SENSITIVITY_KEY] ?: 2 }
    
    suspend fun setQrSensitivity(level: Int) {
        context.dataStore.edit { preferences ->
            preferences[QR_SENSITIVITY_KEY] = level.coerceIn(0, 4)
        }
    }
    
    val scanHistoryEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[SCAN_HISTORY_ENABLED_KEY] ?: true }
    
    suspend fun setScanHistoryEnabled(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[SCAN_HISTORY_ENABLED_KEY] = enabled
        }
    }
    
    // Wi-Fi Auditor Management
    val wifiScanInterval: Flow<Int> = context.dataStore.data
        .map { preferences -> preferences[WIFI_SCAN_INTERVAL_KEY] ?: 30 }
    
    suspend fun setWifiScanInterval(seconds: Int) {
        context.dataStore.edit { preferences ->
            preferences[WIFI_SCAN_INTERVAL_KEY] = seconds.coerceAtLeast(10)
        }
    }
    
    val wifiAutoScan: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[WIFI_AUTO_SCAN_KEY] ?: true }
    
    suspend fun setWifiAutoScan(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[WIFI_AUTO_SCAN_KEY] = enabled
        }
    }
    
    // HIBP Management
    val hibpApiEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[HIBP_API_ENABLED_KEY] ?: true }
    
    suspend fun setHibpApiEnabled(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[HIBP_API_ENABLED_KEY] = enabled
        }
    }
    
    val passwordHistory: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[PASSWORD_HISTORY_KEY] ?: false }
    
    suspend fun setPasswordHistory(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[PASSWORD_HISTORY_KEY] = enabled
        }
    }
    
    // Advanced Management
    val cacheSize: Flow<Int> = context.dataStore.data
        .map { preferences -> preferences[CACHE_SIZE_KEY] ?: 50 }
    
    suspend fun setCacheSize(sizeMB: Int) {
        context.dataStore.edit { preferences ->
            preferences[CACHE_SIZE_KEY] = sizeMB.coerceIn(10, 500)
        }
    }
    
    val debugMode: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[DEBUG_MODE_KEY] ?: false }
    
    suspend fun setDebugMode(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[DEBUG_MODE_KEY] = enabled
        }
    }
    
    // Email Monitoring
    val monitoredEmail: Flow<String?> = context.dataStore.data
        .map { preferences -> preferences[MONITORED_EMAIL_KEY] }
    
    suspend fun setMonitoredEmail(email: String?) {
        context.dataStore.edit { preferences ->
            if (email.isNullOrBlank()) {
                preferences.remove(MONITORED_EMAIL_KEY)
            } else {
                preferences[MONITORED_EMAIL_KEY] = email
            }
        }
    }
    
    // Premium Status
    val isPremium: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[IS_PREMIUM_KEY] ?: false }
    
    suspend fun setPremium(premium: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[IS_PREMIUM_KEY] = premium
        }
    }
    
    // Reset all preferences
    suspend fun resetToDefaults() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }
    
    // Export preferences as map
    suspend fun exportPreferences(): Map<String, Any> {
        val preferences = context.dataStore.data.map { it.asMap() }
        return preferences.toString().let { 
            mapOf("preferences" to it, "timestamp" to System.currentTimeMillis())
        }
    }
}