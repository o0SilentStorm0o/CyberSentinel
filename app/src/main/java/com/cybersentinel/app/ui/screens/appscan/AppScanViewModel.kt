package com.cybersentinel.app.ui.screens.appscan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.domain.security.AppSecurityScanner
import com.cybersentinel.app.domain.security.AppSecurityScanner.*
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class AppScanUiState(
    val isScanning: Boolean = false,
    val scanProgress: Float = 0f,
    val currentScanningApp: String? = null,
    val reports: List<AppSecurityReport> = emptyList(),
    val summary: ScanSummary? = null,
    val filter: AppFilter = AppFilter.ALL,
    val includeSystemApps: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class AppScanViewModel @Inject constructor(
    private val appScanner: AppSecurityScanner
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(AppScanUiState())
    val uiState: StateFlow<AppScanUiState> = _uiState.asStateFlow()
    
    init {
        startScan()
    }
    
    fun startScan() {
        viewModelScope.launch {
            _uiState.update { it.copy(isScanning = true, scanProgress = 0f, error = null) }
            
            try {
                val reports = withContext(Dispatchers.IO) {
                    appScanner.scanAllApps(includeSystem = _uiState.value.includeSystemApps)
                }
                
                val summary = appScanner.getScanSummary(reports)
                
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        scanProgress = 1f,
                        reports = reports,
                        summary = summary,
                        currentScanningApp = null
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        error = e.message ?: "Chyba při skenování"
                    )
                }
            }
        }
    }
    
    fun setFilter(filter: AppFilter) {
        _uiState.update { it.copy(filter = filter) }
    }
    
    fun toggleSystemApps() {
        _uiState.update { it.copy(includeSystemApps = !it.includeSystemApps) }
        startScan()
    }
}
