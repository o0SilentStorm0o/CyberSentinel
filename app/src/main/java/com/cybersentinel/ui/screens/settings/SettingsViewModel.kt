package com.cybersentinel.ui.screens.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.data.preferences.AppPreferences
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel pro Settings screen
 */
@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val appPreferences: AppPreferences
) : ViewModel() {
    
    // Theme
    val isDarkTheme = appPreferences.isDarkTheme
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)
    
    // Notifications
    val notificationsEnabled = appPreferences.notificationsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val cveNotifications = appPreferences.cveNotifications
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // CVE Monitor
    val autoRefresh = appPreferences.autoRefresh
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val refreshInterval = appPreferences.refreshInterval
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 24)
    
    // QR Scanner
    val qrSensitivity = appPreferences.qrSensitivity
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 2)
    
    val scanHistoryEnabled = appPreferences.scanHistoryEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Wi-Fi Auditor
    val wifiScanInterval = appPreferences.wifiScanInterval
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 30)
    
    val wifiAutoScan = appPreferences.wifiAutoScan
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // HIBP
    val hibpApiEnabled = appPreferences.hibpApiEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val passwordHistory = appPreferences.passwordHistory
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)
    
    // Advanced
    val cacheSize = appPreferences.cacheSize
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 50)
    
    val debugMode = appPreferences.debugMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)
    
    // Actions
    fun toggleDarkTheme() {
        viewModelScope.launch {
            appPreferences.setDarkTheme(!isDarkTheme.value)
        }
    }
    
    fun toggleNotifications() {
        viewModelScope.launch {
            appPreferences.setNotificationsEnabled(!notificationsEnabled.value)
        }
    }
    
    fun toggleCveNotifications() {
        viewModelScope.launch {
            appPreferences.setCveNotifications(!cveNotifications.value)
        }
    }
    
    fun toggleAutoRefresh() {
        viewModelScope.launch {
            appPreferences.setAutoRefresh(!autoRefresh.value)
        }
    }
    
    fun setRefreshInterval(hours: Int) {
        viewModelScope.launch {
            appPreferences.setRefreshInterval(hours)
        }
    }
    
    fun setQrSensitivity(level: Int) {
        viewModelScope.launch {
            appPreferences.setQrSensitivity(level)
        }
    }
    
    fun toggleScanHistory() {
        viewModelScope.launch {
            appPreferences.setScanHistoryEnabled(!scanHistoryEnabled.value)
        }
    }
    
    fun setWifiScanInterval(seconds: Int) {
        viewModelScope.launch {
            appPreferences.setWifiScanInterval(seconds)
        }
    }
    
    fun toggleWifiAutoScan() {
        viewModelScope.launch {
            appPreferences.setWifiAutoScan(!wifiAutoScan.value)
        }
    }
    
    fun toggleHibpApi() {
        viewModelScope.launch {
            appPreferences.setHibpApiEnabled(!hibpApiEnabled.value)
        }
    }
    
    fun togglePasswordHistory() {
        viewModelScope.launch {
            appPreferences.setPasswordHistory(!passwordHistory.value)
        }
    }
    
    fun setCacheSize(sizeMB: Int) {
        viewModelScope.launch {
            appPreferences.setCacheSize(sizeMB)
        }
    }
    
    fun toggleDebugMode() {
        viewModelScope.launch {
            appPreferences.setDebugMode(!debugMode.value)
        }
    }
    
    fun resetAllSettings() {
        viewModelScope.launch {
            appPreferences.resetToDefaults()
        }
    }
    
    fun clearCache() {
        viewModelScope.launch {
            // TODO: Implementovat cache clearing
        }
    }
    
    fun exportSettings() {
        viewModelScope.launch {
            val exported = appPreferences.exportPreferences()
            // TODO: Save to file or share
        }
    }
}