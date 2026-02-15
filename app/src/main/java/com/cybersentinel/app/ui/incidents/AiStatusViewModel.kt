package com.cybersentinel.app.ui.incidents

import android.os.Environment
import android.os.StatFs
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.domain.capability.FeatureGatekeeper
import com.cybersentinel.app.domain.capability.GateRule
import com.cybersentinel.app.domain.explainability.ExplanationOrchestrator
import com.cybersentinel.app.domain.llm.ModelManager
import com.cybersentinel.app.domain.llm.ModelManifest
import com.cybersentinel.app.domain.llm.ModelOperationResult
import com.cybersentinel.app.domain.llm.ModelState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * AiStatusViewModel — drives the "AI & Model" status/settings screen.
 *
 * Shows: model state, capability tier, gate status, self-test results,
 * kill switch state, user toggle.
 *
 * Sprint UI-2: 5/10 — real download/remove/self-test wiring.
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
    private var isDownloading = false
    private var isSelfTesting = false

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

    // ══════════════════════════════════════════════════════════
    //  Download
    // ══════════════════════════════════════════════════════════

    /**
     * Start model download using ModelManager.
     * Uses a hardcoded manifest for MVP — will come from remote config later.
     */
    fun onDownloadClick(targetDir: File) {
        if (isDownloading) return

        isDownloading = true
        _ui.update { it.copy(downloadProgress = 0f) }

        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                modelManager.downloadModel(
                    manifest = getDefaultManifest(),
                    targetDir = targetDir,
                    onProgress = { progress ->
                        val fraction = if (progress.totalBytes > 0)
                            progress.downloadedBytes.toFloat() / progress.totalBytes
                        else 0f
                        _ui.update { it.copy(downloadProgress = fraction) }
                    }
                )
            }

            isDownloading = false
            when (result) {
                is ModelOperationResult.Success -> {
                    refresh()
                }
                is ModelOperationResult.Failure -> {
                    _ui.update { it.copy(downloadProgress = null, downloadError = result.error) }
                }
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Remove model
    // ══════════════════════════════════════════════════════════

    fun onRemoveClick() {
        modelManager.deleteModel()
        lastSelfTestReady = null
        lastSelfTestSummary = null
        refresh()
    }

    // ══════════════════════════════════════════════════════════
    //  Self-test
    // ══════════════════════════════════════════════════════════

    /**
     * Store self-test results from LlmSelfTestRunner (called by whoever runs the test).
     */
    fun onSelfTestCompleted(isProductionReady: Boolean, summary: String) {
        lastSelfTestReady = isProductionReady
        lastSelfTestSummary = summary
        isSelfTesting = false
        refresh()
    }

    fun onSelfTestStarted() {
        isSelfTesting = true
        refresh()
    }

    // ══════════════════════════════════════════════════════════
    //  Gate helpers
    // ══════════════════════════════════════════════════════════

    /**
     * Human-readable reason for a gate rule (Czech).
     */
    internal fun gateReasonLabel(rule: GateRule): String {
        return when (rule) {
            GateRule.TIER_BLOCKED -> "Zařízení nemá dostatečný výkon pro AI"
            GateRule.KILL_SWITCH -> "AI model byl zakázán administrátorem"
            GateRule.USER_DISABLED -> "AI je vypnuté uživatelem"
            GateRule.LOW_RAM -> "Nedostatek paměti RAM"
            GateRule.POWER_SAVER -> "Režim úspory energie je aktivní"
            GateRule.THERMAL_THROTTLE -> "Zařízení se přehřívá"
            GateRule.BACKGROUND_RESTRICTED -> "Aplikace běží na pozadí"
            GateRule.ALLOWED -> "Vše v pořádku"
        }
    }

    // ══════════════════════════════════════════════════════════
    //  UI model builder
    // ══════════════════════════════════════════════════════════

    private fun buildUiModel(): AiStatusUiModel {
        val tier = featureGatekeeper.getCapabilityTier()
        val gateDecision = featureGatekeeper.checkGate()
        val modelState = modelManager.getState()

        val modelStateLabel = when (modelState) {
            ModelState.NOT_DOWNLOADED -> "Nestažen"
            ModelState.DOWNLOADING -> "Stahování…"
            ModelState.READY -> "Připraven"
            ModelState.LOADED -> "Načten v paměti"
            ModelState.CORRUPTED -> "Poškozený"
            ModelState.KILLED -> "Zakázán (kill switch)"
        }

        val availableStorage = try {
            val stat = StatFs(Environment.getDataDirectory().path)
            stat.availableBlocksLong * stat.blockSizeLong / (1024 * 1024)
        } catch (_: Exception) { null }

        return AiStatusUiModel(
            modelStateLabel = modelStateLabel,
            tierLabel = tier.label,
            llmAvailable = gateDecision.allowed,
            gateReason = gateReasonLabel(gateDecision.rule),
            downloadProgress = if (isDownloading) _ui.value.downloadProgress else null,
            modelSizeMb = modelManager.getModelInfo()?.fileSizeBytes?.let { it / (1024 * 1024) },
            availableStorageMb = availableStorage,
            selfTestCompleted = lastSelfTestReady != null,
            isProductionReady = lastSelfTestReady,
            selfTestSummary = lastSelfTestSummary,
            killSwitchActive = modelManager.isKillSwitchActive(),
            userLlmEnabled = featureGatekeeper.userLlmEnabled,
            canDownload = modelState == ModelState.NOT_DOWNLOADED || modelState == ModelState.CORRUPTED,
            canRemove = modelState == ModelState.READY || modelState == ModelState.LOADED,
            isSelfTesting = isSelfTesting,
            downloadError = null
        )
    }

    /**
     * Default model manifest for MVP. In production, this comes from remote config.
     */
    private fun getDefaultManifest() = ModelManifest(
        modelId = "cybersentinel-v1",
        displayName = "CyberSentinel AI v1",
        version = "1.0.0",
        downloadUrl = "https://models.cybersentinel.app/cybersentinel-v1.gguf",
        sha256 = "placeholder-sha256",
        fileSizeBytes = 500_000_000L,
        requires64Bit = true,
        quantization = "Q4_K_M"
    )
}
