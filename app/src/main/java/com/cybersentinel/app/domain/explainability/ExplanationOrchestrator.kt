package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.capability.FeatureGatekeeper
import com.cybersentinel.app.domain.capability.GateRule
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ExplanationOrchestrator — single entry point for producing user-facing explanations.
 *
 * Flow:
 *  1. Check FeatureGatekeeper → can we use LLM?
 *  2. If yes AND LLM engine available → use LLM engine
 *  3. If no (tier blocked, runtime gate, kill switch, user disabled) → use Template engine
 *  4. Apply PolicyGuard validation (done by the engine, but we double-check)
 *  5. Return ExplanationAnswer with engine attribution
 *
 * Fallback guarantee: Template engine is ALWAYS available.
 * The orchestrator NEVER returns an error — worst case is template fallback.
 *
 * Future (Sprint C): LLM engine will be injected here. For now, only Template engine.
 *
 * Thread safety: Stateless orchestration, delegates to thread-safe components.
 */
@Singleton
class ExplanationOrchestrator @Inject constructor(
    private val templateEngine: TemplateExplanationEngine,
    private val policyGuard: PolicyGuard,
    private val featureGatekeeper: FeatureGatekeeper
) {

    /**
     * Produce an explanation for the given request.
     *
     * This is what the UI calls. It handles all engine selection, fallback,
     * and policy validation transparently.
     *
     * @param request The explanation request
     * @param modelId LLM model version to check kill switch (default = "default")
     * @param isInBackground Whether the app is currently in background
     * @return Structured, policy-validated ExplanationAnswer
     */
    fun explain(
        request: ExplanationRequest,
        modelId: String = "default",
        isInBackground: Boolean = false
    ): ExplanationAnswer {
        // 1. Check if LLM is available
        val gateDecision = featureGatekeeper.checkGate(modelId, isInBackground)

        // 2. Select engine
        val answer = if (gateDecision.allowed && llmEngine != null) {
            // Try LLM engine, fallback to template on failure
            tryLlmWithFallback(request)
        } else {
            // Use template engine directly
            templateEngine.explain(request)
        }

        // 3. Double-check PolicyGuard (engines should already apply it, but defense in depth)
        return policyGuard.validate(answer, request.incident)
    }

    /**
     * Force template-only explanation (bypass gate check).
     * Useful for testing, debugging, or when user explicitly wants deterministic output.
     */
    fun explainWithTemplate(request: ExplanationRequest): ExplanationAnswer {
        return templateEngine.explain(request)
    }

    /**
     * Get the current engine selection rationale for diagnostics/UI.
     *
     * @return Human-readable explanation of which engine would be selected and why
     */
    fun getEngineSelectionRationale(
        modelId: String = "default",
        isInBackground: Boolean = false
    ): EngineSelectionInfo {
        val gateDecision = featureGatekeeper.checkGate(modelId, isInBackground)
        val tier = featureGatekeeper.getCapabilityTier()

        val selectedEngine = if (gateDecision.allowed && llmEngine != null) {
            EngineSource.LLM_ASSISTED
        } else if (gateDecision.allowed && llmEngine == null) {
            EngineSource.TEMPLATE // LLM capable but no LLM engine installed yet
        } else {
            EngineSource.TEMPLATE
        }

        return EngineSelectionInfo(
            selectedEngine = selectedEngine,
            tier = tier,
            gateAllowed = gateDecision.allowed,
            gateReason = gateDecision.reason,
            gateRule = gateDecision.rule,
            llmEngineAvailable = llmEngine?.isAvailable ?: false,
            userLlmEnabled = featureGatekeeper.userLlmEnabled
        )
    }

    // ══════════════════════════════════════════════════════════
    //  LLM engine slot (for Sprint C injection)
    // ══════════════════════════════════════════════════════════

    /**
     * LLM engine — null until Sprint C. Set via setLlmEngine().
     *
     * Not injected via Hilt because the LLM module is optional and may not
     * be present on all builds / devices.
     */
    @Volatile
    private var llmEngine: ExplanationEngine? = null

    /**
     * Register an LLM engine. Called by Sprint C LLM module initialization.
     */
    fun setLlmEngine(engine: ExplanationEngine) {
        llmEngine = engine
    }

    /**
     * Unregister LLM engine (e.g., on model unload or kill switch activation).
     */
    fun clearLlmEngine() {
        llmEngine = null
    }

    /**
     * Try LLM engine, fall back to template on any failure.
     */
    private fun tryLlmWithFallback(request: ExplanationRequest): ExplanationAnswer {
        return try {
            val engine = llmEngine ?: return templateEngine.explain(request)
            if (!engine.isAvailable) {
                return templateEngine.explain(request).copy(
                    engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE
                )
            }
            engine.explain(request)
        } catch (_: Exception) {
            // LLM failed — silent fallback to template
            templateEngine.explain(request).copy(
                engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE
            )
        }
    }
}

/**
 * Diagnostic info about which engine was selected and why.
 * Used by UI to show "AI status" indicator and settings screen.
 */
data class EngineSelectionInfo(
    val selectedEngine: EngineSource,
    val tier: com.cybersentinel.app.domain.capability.CapabilityTier,
    val gateAllowed: Boolean,
    val gateReason: String,
    val gateRule: GateRule,
    val llmEngineAvailable: Boolean,
    val userLlmEnabled: Boolean
) {
    /** Human-readable status for UI */
    val statusText: String
        get() = when (selectedEngine) {
            EngineSource.TEMPLATE ->
                if (!gateAllowed) "Šablonový engine (${gateReason})"
                else if (!llmEngineAvailable) "Šablonový engine (AI modul není nainstalován)"
                else "Šablonový engine"
            EngineSource.LLM_ASSISTED -> "AI asistovaný engine"
            EngineSource.LLM_FALLBACK_TO_TEMPLATE -> "Šablonový engine (záloha za AI)"
        }
}
