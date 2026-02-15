package com.cybersentinel.app.ui.incidents

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.data.local.SecurityEventDao
import com.cybersentinel.app.domain.capability.FeatureGatekeeper
import com.cybersentinel.app.domain.capability.GateRule
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
 * Sprint UI-2: 6/10 — gate enforcement (disable Explain when gate=NO).
 */
@HiltViewModel
class IncidentDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val securityEventDao: SecurityEventDao,
    private val rootCauseResolver: RootCauseResolver,
    private val orchestrator: ExplanationOrchestrator,
    private val featureGatekeeper: FeatureGatekeeper
) : ViewModel() {

    /** Event ID from navigation argument */
    private val eventId: String = savedStateHandle.get<String>("eventId") ?: ""

    data class UiState(
        val isLoading: Boolean = true,
        val detail: IncidentDetailModel? = null,
        val explanationState: ExplanationUiState = ExplanationUiState.Idle,
        val error: String? = null,
        /** True if the "Explain" button should be enabled (gate is open) */
        val canExplainWithAi: Boolean = false,
        /** Reason why AI is not available (shown to user when gate=NO) */
        val gateBlockReason: String? = null
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

                // Check gate status
                val gateDecision = featureGatekeeper.checkGate()
                val gateBlockReason = if (!gateDecision.allowed) {
                    gateReasonLabel(gateDecision.rule)
                } else null

                _ui.update {
                    it.copy(
                        isLoading = false,
                        detail = detail,
                        canExplainWithAi = gateDecision.allowed,
                        gateBlockReason = gateBlockReason
                    )
                }
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

        // Re-check gate before launching LLM
        val gateDecision = featureGatekeeper.checkGate()
        if (!gateDecision.allowed) {
            _ui.update {
                it.copy(
                    canExplainWithAi = false,
                    gateBlockReason = gateReasonLabel(gateDecision.rule)
                )
            }
            return
        }

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
                val userMessage = LlmErrorMapper.toUserMessage(e.message ?: "")
                _ui.update {
                    it.copy(explanationState = ExplanationUiState.Error(userMessage))
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

    /**
     * Human-readable reason for gate denial (Czech).
     * Uses shared static method for consistency with AI & Model screen.
     */
    private fun gateReasonLabel(rule: GateRule): String {
        return AiStatusViewModel.gateReasonLabelStatic(rule)
    }
}
