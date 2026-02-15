package com.cybersentinel.app.ui.incidents

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.data.local.SecurityEventDao
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.IncidentStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * IncidentListViewModel — drives the incident list screen.
 *
 * Data flow (UI-2 optimized — no resolve() in list):
 *  1. SecurityEventDao.getActiveEvents() → List<SecurityEventEntity>
 *  2. IncidentMapper.toCardFromEntity() → List<IncidentCardModel>
 *  3. Already sorted by DAO (severity desc, then time desc)
 *
 * RootCauseResolver.resolve() is ONLY used in IncidentDetailViewModel.
 *
 * Sprint UI-2: 4/10 — list performance, no resolve in list.
 */
@HiltViewModel
class IncidentListViewModel @Inject constructor(
    private val securityEventDao: SecurityEventDao
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
                // Active events: CRITICAL/HIGH/MEDIUM + anything from last 7 days
                val recentCutoff = System.currentTimeMillis() - RECENT_WINDOW_MS
                val entities = withContext(Dispatchers.IO) {
                    securityEventDao.getActiveEvents(recentCutoff)
                }

                // Entity → card directly, no resolve()
                val cards = entities.map { IncidentMapper.toCardFromEntity(it) }

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

    companion object {
        /** Include LOW/INFO events from the last 7 days. */
        const val RECENT_WINDOW_MS = 7L * 24 * 60 * 60 * 1000
    }
}
