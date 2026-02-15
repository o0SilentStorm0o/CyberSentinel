package com.cybersentinel.app.ui.incidents

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.domain.capability.CapabilityTier
import com.cybersentinel.app.domain.capability.FeatureGatekeeper
import com.cybersentinel.app.domain.explainability.ExplanationOrchestrator
import com.cybersentinel.app.domain.llm.ModelManager
import com.cybersentinel.app.domain.llm.ModelState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AiStatusViewModel — drives the "AI & Model" status/settings screen.
 *
 * Shows: model state, capability tier, gate status, self-test results,
 * kill switch state, user toggle.
 *
 * Sprint UI-1: Model manager UI.
 */
@HiltViewModel
class AiStatusViewModel @Inject constructor(
    private val modelManager: ModelManager,
    private val featureGatekeeper: FeatureGatekeeper,
    private val orchestrator: ExplanationOrchestrator
) : ViewModel() {

    private val _ui = MutableStateFlow(buildUiModel())
    val ui: StateFlow<AiStatusUiModel> = _ui.asStateFlow()

    /** Last self-test summary (if any) */
    private var lastSelfTestSummary: String? = null
    private var lastSelfTestReady: Boolean? = null

    init {
        refresh()
    }

    fun refresh() {
        _ui.update { buildUiModel() }
    }

    fun toggleUserLlm(enabled: Boolean) {
        featureGatekeeper.userLlmEnabled = enabled
        refresh()
    }

    /**
     * Store self-test results from LlmSelfTestRunner (called by whoever runs the test).
     */
    fun onSelfTestCompleted(isProductionReady: Boolean, summary: String) {
        lastSelfTestReady = isProductionReady
        lastSelfTestSummary = summary
        refresh()
    }

    private fun buildUiModel(): AiStatusUiModel {
        val tier = featureGatekeeper.getCapabilityTier()
        val gateDecision = featureGatekeeper.checkGate()
        val modelState = modelManager.getState()
        val info = orchestrator.getEngineSelectionRationale()

        val modelStateLabel = when (modelState) {
            ModelState.NOT_DOWNLOADED -> "Nestažen"
            ModelState.DOWNLOADING -> "Stahování…"
            ModelState.READY -> "Připraven"
            ModelState.LOADED -> "Načten v paměti"
            ModelState.CORRUPTED -> "Poškozený"
            ModelState.KILLED -> "Zakázán (kill switch)"
        }

        return AiStatusUiModel(
            modelStateLabel = modelStateLabel,
            tierLabel = tier.label,
            llmAvailable = gateDecision.allowed,
            gateReason = gateDecision.reason,
            downloadProgress = null, // TODO: wire download progress stream
            modelSizeMb = modelManager.getModelInfo()?.fileSizeBytes?.let { it / (1024 * 1024) },
            availableStorageMb = null, // TODO: wire from DeviceProfiler
            selfTestCompleted = lastSelfTestReady != null,
            isProductionReady = lastSelfTestReady,
            selfTestSummary = lastSelfTestSummary,
            killSwitchActive = modelManager.isKillSwitchActive(),
            userLlmEnabled = featureGatekeeper.userLlmEnabled
        )
    }
}
