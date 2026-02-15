package com.cybersentinel.app.ui.incidents

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.data.local.SecurityEventDao
import com.cybersentinel.app.domain.security.DefaultRootCauseResolver
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.IncidentStatus
import com.cybersentinel.app.domain.security.RootCauseResolver
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * IncidentListViewModel — drives the incident list screen.
 *
 * Data flow:
 *  1. SecurityEventDao.getAll() → List<SecurityEventEntity>
 *  2. IncidentMapper.toDomain() → List<SecurityEvent>
 *  3. RootCauseResolver.resolve() → List<SecurityIncident>
 *  4. IncidentMapper.toCardModel() → List<IncidentCardModel>
 *  5. Sort: severity desc, then createdAt desc
 *
 * Sprint UI-1: Incident list MVP.
 */
@HiltViewModel
class IncidentListViewModel @Inject constructor(
    private val securityEventDao: SecurityEventDao,
    private val rootCauseResolver: RootCauseResolver
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = true,
        val incidents: List<IncidentCardModel> = emptyList(),
        val activeCount: Int = 0,
        val error: String? = null
    )

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    init {
        loadIncidents()
    }

    fun loadIncidents() {
        viewModelScope.launch {
            _ui.update { it.copy(isLoading = true, error = null) }
            try {
                val entities = securityEventDao.getAll()
                val events = entities.map { IncidentMapper.toDomain(it) }

                val incidents = events.map { event ->
                    rootCauseResolver.resolve(event)
                }

                val cards = incidents
                    .map { IncidentMapper.toCardModel(it) }
                    .sortedWith(
                        compareByDescending<IncidentCardModel> { severityOrder(it.severity) }
                            .thenByDescending { it.createdAt }
                    )

                val activeCount = cards.count {
                    it.status == IncidentStatus.OPEN || it.status == IncidentStatus.INVESTIGATING
                }

                _ui.update {
                    it.copy(
                        isLoading = false,
                        incidents = cards,
                        activeCount = activeCount
                    )
                }
            } catch (e: Exception) {
                _ui.update {
                    it.copy(isLoading = false, error = "Chyba při načítání incidentů: ${e.message}")
                }
            }
        }
    }

    /**
     * Numeric order for severity sorting (higher = more severe).
     */
    private fun severityOrder(severity: IncidentSeverity): Int {
        return when (severity) {
            IncidentSeverity.CRITICAL -> 5
            IncidentSeverity.HIGH -> 4
            IncidentSeverity.MEDIUM -> 3
            IncidentSeverity.LOW -> 2
            IncidentSeverity.INFO -> 1
        }
    }
}
