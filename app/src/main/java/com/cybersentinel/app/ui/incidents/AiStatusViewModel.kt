package com.cybersentinel.app.ui.incidents

import android.os.Environment
import android.os.StatFs
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.domain.capability.FeatureGatekeeper
import com.cybersentinel.app.domain.capability.GateRule
import com.cybersentinel.app.domain.explainability.ExplanationOrchestrator
import com.cybersentinel.app.domain.llm.LlmBenchmarkResult
import com.cybersentinel.app.domain.llm.LlmSelfTestRunner
import com.cybersentinel.app.domain.llm.ModelManager
import com.cybersentinel.app.domain.llm.ModelManifest
import com.cybersentinel.app.domain.llm.ModelOperationResult
import com.cybersentinel.app.domain.llm.ModelState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * AiStatusViewModel — drives the "AI & Model" control panel screen.
 *
 * Full lifecycle: Download → (auto-load) → Self-test → Ready
 * Cancel download, remove model, re-download on failure.
 *
 * Sprint UI-3: Complete control panel with self-test integration + metrics.
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
    private var lastBenchmarkResult: LlmBenchmarkResult? = null
    private var isDownloading = false
    private var isSelfTesting = false
    private var downloadJob: Job? = null

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
        _ui.update { it.copy(downloadProgress = 0f, downloadError = null) }

        downloadJob = viewModelScope.launch {
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
            downloadJob = null
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

    /**
     * Cancel an in-progress download and clean up partial files.
     */
    fun onCancelDownload() {
        downloadJob?.cancel()
        downloadJob = null
        isDownloading = false
        // ModelManager will leave partial file; we just reset UI
        _ui.update { it.copy(downloadProgress = null, downloadError = null) }
        refresh()
    }

    // ══════════════════════════════════════════════════════════
    //  Remove model
    // ══════════════════════════════════════════════════════════

    fun onRemoveClick() {
        modelManager.deleteModel()
        lastSelfTestReady = null
        lastSelfTestSummary = null
        lastBenchmarkResult = null
        refresh()
    }

    /**
     * Remove and re-download in one action (for failed/corrupted models).
     */
    fun onRedownloadClick(targetDir: File) {
        modelManager.deleteModel()
        lastSelfTestReady = null
        lastSelfTestSummary = null
        lastBenchmarkResult = null
        onDownloadClick(targetDir)
    }

    // ══════════════════════════════════════════════════════════
    //  Self-test
    // ══════════════════════════════════════════════════════════

    /**
     * Run self-test in ViewModel scope using the provided runner.
     * This is the primary entry point — runs on IO dispatcher.
     */
    fun runSelfTest(runner: LlmSelfTestRunner) {
        if (isSelfTesting) return
        isSelfTesting = true
        refresh()

        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runner.runSmokeTest(
                        modelId = getDefaultManifest().modelId,
                        modelVersion = getDefaultManifest().version
                    )
                }
                // Also run a fuller benchmark for metrics display
                val benchmarkResult = withContext(Dispatchers.IO) {
                    runner.runBenchmark(
                        runs = 10,
                        modelId = getDefaultManifest().modelId,
                        modelVersion = getDefaultManifest().version
                    )
                }

                lastSelfTestReady = benchmarkResult.isProductionReady
                lastSelfTestSummary = benchmarkResult.summary
                lastBenchmarkResult = benchmarkResult
            } catch (e: Exception) {
                lastSelfTestReady = false
                lastSelfTestSummary = "Self-test selhal: ${e.message}"
                lastBenchmarkResult = null
            } finally {
                isSelfTesting = false
                refresh()
            }
        }
    }

    /**
     * Store self-test results from external runner (backward compat).
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
     * Consistent with IncidentDetailViewModel.gateReasonLabel().
     */
    internal fun gateReasonLabel(rule: GateRule): String {
        return gateReasonLabelStatic(rule)
    }

    // ══════════════════════════════════════════════════════════
    //  Metrics extraction
    // ══════════════════════════════════════════════════════════

    /**
     * Extract user-facing metrics from benchmark result.
     * Shows only decision-relevant metrics; rest goes into "advanced".
     */
    internal fun extractMetrics(result: LlmBenchmarkResult): BenchmarkMetricsUi {
        val reliability = (result.quality.schemaComplianceRate * 100).toInt()
        val policyViolationRate = if (result.totalRuns > 0)
            (result.quality.policyViolationCount.toFloat() / result.totalRuns * 100) else 0f

        return BenchmarkMetricsUi(
            isProductionReady = result.isProductionReady,
            healthScore = (result.healthScore * 100).toInt(),
            avgLatencyMs = result.latency.avgMs,
            p95LatencyMs = result.latency.p95Ms,
            reliabilityPercent = reliability,
            policyViolationPercent = policyViolationRate,
            peakHeapMb = if (result.peakNativeHeapBytes > 0)
                result.peakNativeHeapBytes / (1024 * 1024) else null,
            totalRuns = result.totalRuns,
            // Advanced metrics
            p99LatencyMs = result.latency.p99Ms,
            avgTokensPerSecond = result.latency.avgTokensPerSecond,
            templateFallbackPercent = (result.pipeline.templateFallbackRate * 100).toInt(),
            stopFailurePercent = (result.stopFailureRate * 100),
            avgGeneratedTokens = result.avgGeneratedTokens,
            maxGeneratedTokens = result.maxGeneratedTokens,
            oomCount = result.stability.oomCount,
            timeoutCount = result.stability.timeoutCount
        )
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

        val metrics = lastBenchmarkResult?.let { extractMetrics(it) }

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
            downloadError = _ui.value.downloadError,
            isDownloading = isDownloading,
            benchmarkMetrics = metrics
        )
    }

    /**
     * Default model manifest for MVP. In production, this comes from remote config.
     */
    internal fun getDefaultManifest() = ModelManifest(
        modelId = "cybersentinel-v1",
        displayName = "CyberSentinel AI v1",
        version = "1.0.0",
        downloadUrl = "https://models.cybersentinel.app/cybersentinel-v1.gguf",
        sha256 = "placeholder-sha256",
        fileSizeBytes = 500_000_000L,
        requires64Bit = true,
        quantization = "Q4_K_M"
    )

    companion object {
        /**
         * Shared gate reason label — used by both AiStatusViewModel
         * and IncidentDetailViewModel for consistency.
         */
        fun gateReasonLabelStatic(rule: GateRule): String {
            return when (rule) {
                GateRule.TIER_BLOCKED ->
                    "AI je dostupná pouze na arm64 zařízeních (emulátor/x86 není podporován)"
                GateRule.KILL_SWITCH -> "AI model byl zakázán administrátorem"
                GateRule.USER_DISABLED -> "AI je vypnuté uživatelem v nastavení"
                GateRule.LOW_RAM -> "Nedostatek paměti RAM pro AI inferenci"
                GateRule.POWER_SAVER -> "Režim úspory energie je aktivní"
                GateRule.THERMAL_THROTTLE -> "Zařízení se přehřívá — AI je pozastavena"
                GateRule.BACKGROUND_RESTRICTED -> "Aplikace běží na pozadí — AI šetří prostředky"
                GateRule.ALLOWED -> "AI je připravena k použití"
            }
        }
    }
}
