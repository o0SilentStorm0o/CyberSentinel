package com.cybersentinel.app.ui.incidents

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.data.local.SecurityEventDao
import com.cybersentinel.app.domain.explainability.ExplanationOrchestrator
import com.cybersentinel.app.domain.explainability.ExplanationRequest
import com.cybersentinel.app.domain.security.RootCauseResolver
import com.cybersentinel.app.domain.security.SecurityIncident
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * IncidentDetailViewModel — drives the incident detail screen.
 *
 * Data flow on open:
 *  1. DAO loads SecurityEventEntity by eventId (from navigation arg)
 *  2. IncidentMapper.toDomain() → SecurityEvent
 *  3. RootCauseResolver.resolve() → SecurityIncident
 *  4. Template explanation (always, instant) → IncidentDetailModel
 *
 * On "Vysvětlit" button press:
 *  5. ExplanationOrchestrator.explain() → ExplanationAnswer (may use LLM if available)
 *  6. IncidentMapper.toDetailModel() → IncidentDetailModel (replaces template version)
 *
 * Sprint UI-1: Incident detail MVP.
 */
@HiltViewModel
class IncidentDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val securityEventDao: SecurityEventDao,
    private val rootCauseResolver: RootCauseResolver,
    private val orchestrator: ExplanationOrchestrator
) : ViewModel() {

    /** Event ID from navigation argument */
    private val eventId: String = savedStateHandle.get<String>("eventId") ?: ""

    data class UiState(
        val isLoading: Boolean = true,
        val detail: IncidentDetailModel? = null,
        val explanationState: ExplanationUiState = ExplanationUiState.Idle,
        val error: String? = null
    )

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    /** Cached incident for re-explain */
    private var cachedIncident: SecurityIncident? = null

    /** Active explain job for cancel */
    private var explainJob: Job? = null

    init {
        if (eventId.isNotBlank()) {
            loadDetail()
        }
    }

    private fun loadDetail() {
        viewModelScope.launch {
            _ui.update { it.copy(isLoading = true, error = null) }
            try {
                val entities = withContext(Dispatchers.IO) {
                    securityEventDao.getAll()
                }
                val entity = entities.find { it.id == eventId }
                if (entity == null) {
                    _ui.update { it.copy(isLoading = false, error = "Incident nenalezen") }
                    return@launch
                }

                val event = IncidentMapper.toDomain(entity)
                val incident = rootCauseResolver.resolve(event)
                cachedIncident = incident

                // Immediate template explanation (always available, instant)
                val request = ExplanationRequest(incident)
                val answer = orchestrator.explainWithTemplate(request)
                val detail = IncidentMapper.toDetailModel(incident, answer)

                _ui.update { it.copy(isLoading = false, detail = detail) }
            } catch (e: Exception) {
                _ui.update {
                    it.copy(isLoading = false, error = "Chyba: ${e.message}")
                }
            }
        }
    }

    /**
     * On-demand "Vysvětlit" button — uses orchestrator (may invoke LLM).
     * Shows loading state, supports cancel.
     */
    fun requestExplanation() {
        val incident = cachedIncident ?: return

        explainJob?.cancel()
        explainJob = viewModelScope.launch {
            _ui.update { it.copy(explanationState = ExplanationUiState.Loading()) }
            try {
                val answer = withContext(Dispatchers.IO) {
                    orchestrator.explain(ExplanationRequest(incident))
                }
                val detail = IncidentMapper.toDetailModel(incident, answer)
                _ui.update {
                    it.copy(
                        detail = detail,
                        explanationState = ExplanationUiState.Ready(detail)
                    )
                }
            } catch (e: Exception) {
                _ui.update {
                    it.copy(explanationState = ExplanationUiState.Error("Vysvětlení selhalo: ${e.message}"))
                }
            }
        }
    }

    /**
     * Cancel in-progress explanation.
     */
    fun cancelExplanation() {
        explainJob?.cancel()
        _ui.update { it.copy(explanationState = ExplanationUiState.Idle) }
    }
}
