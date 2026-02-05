package com.cybersentinel.app.ui.screens.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.domain.security.*
import com.cybersentinel.data.preferences.AppPreferences
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DashboardUiState(
    val isLoading: Boolean = true,
    val isScanning: Boolean = false,
    val securityScore: SecurityScore? = null,
    val lastScanTime: Long? = null,
    val monitoredEmail: String? = null,
    val isPremium: Boolean = false
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val scoreEngine: SecurityScoreEngine,
    private val deviceAnalyzer: DeviceSecurityAnalyzer,
    private val appsScanner: InstalledAppsScanner,
    private val preferences: AppPreferences
) : ViewModel() {
    
    private val _ui = MutableStateFlow(DashboardUiState())
    val ui: StateFlow<DashboardUiState> = _ui.asStateFlow()
    
    init {
        loadInitialState()
    }
    
    private fun loadInitialState() {
        viewModelScope.launch {
            // Load saved email and premium status
            combine(
                preferences.monitoredEmail,
                preferences.isPremium
            ) { email, premium ->
                _ui.update { it.copy(monitoredEmail = email, isPremium = premium) }
            }.collect()
        }
        
        // Run initial scan
        runSecurityScan()
    }
    
    fun runSecurityScan() {
        viewModelScope.launch {
            _ui.update { it.copy(isScanning = true) }
            
            try {
                // 1. Device analysis
                val deviceIssues = deviceAnalyzer.analyzeDevice()
                
                // 2. Apps analysis
                val apps = appsScanner.getInstalledApps()
                val vulnerableApps = appsScanner.findVulnerableApps(apps)
                val appIssues = vulnerableApps.map { vuln ->
                    SecurityIssue(
                        id = "app_vuln_${vuln.app.packageName}",
                        title = "Zranitelná aplikace: ${vuln.app.appName}",
                        description = vuln.description,
                        impact = "Útočník může zneužít známou zranitelnost v této aplikaci k získání přístupu k vašim datům nebo kontroly nad zařízením.",
                        severity = SecurityIssue.Severity.HIGH,
                        category = SecurityIssue.Category.APPS,
                        action = IssueAction.OpenPlayStore(
                            packageName = vuln.app.packageName,
                            label = "Aktualizovat v Play Store"
                        ),
                        confidence = SecurityIssue.Confidence.MEDIUM,
                        source = "CVE databáze"
                    )
                }
                
                // 3. Network issues (from last Wi-Fi scan, simplified)
                val networkIssues = emptyList<SecurityIssue>() // TODO: integrate with Wi-Fi auditor
                
                // 4. Account issues (from HIBP checks, simplified)
                val accountIssues = emptyList<SecurityIssue>() // TODO: integrate with email monitor
                
                // Calculate overall score
                val score = scoreEngine.calculateScore(
                    deviceIssues = deviceIssues,
                    appIssues = appIssues,
                    networkIssues = networkIssues,
                    accountIssues = accountIssues
                )
                
                _ui.update { 
                    it.copy(
                        isLoading = false,
                        isScanning = false,
                        securityScore = score,
                        lastScanTime = System.currentTimeMillis()
                    )
                }
                
            } catch (e: Exception) {
                _ui.update { it.copy(isLoading = false, isScanning = false) }
            }
        }
    }
    
    fun setMonitoredEmail(email: String) {
        viewModelScope.launch {
            preferences.setMonitoredEmail(email)
            _ui.update { it.copy(monitoredEmail = email) }
        }
    }
}
