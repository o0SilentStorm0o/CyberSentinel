package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.EngineSource
import com.cybersentinel.app.domain.explainability.ExplanationAnswer
import com.cybersentinel.app.domain.explainability.ExplanationEngine
import com.cybersentinel.app.domain.explainability.ExplanationRequest
import com.cybersentinel.app.domain.explainability.PolicyGuard
import com.cybersentinel.app.domain.explainability.TemplateExplanationEngine

/**
 * LocalLlmExplanationEngine — full ExplanationEngine implementation for on-device LLM.
 *
 * Pipeline:
 *  1. PolicyGuard.determineConstraints(incident) → SafeLanguageFlags
 *  2. PromptBuilder.buildPrompt(incident, constraints) → prompt string
 *  3. LlmRuntime.runInference(prompt, config) → InferenceResult
 *  4. SlotParser.parse(rawOutput) → ParseResult
 *  5. SlotValidator.validate(slots, incident) → ValidationResult
 *  6. TemplateExplanationEngine.renderFromSlots(validatedSlots, incident) → ExplanationAnswer
 *  7. PolicyGuard.validate(answer, incident) → final answer (with LLM_ASSISTED source)
 *
 * Fallback guarantee: Any failure at steps 2-5 → TemplateExplanationEngine.explain() with
 * LLM_FALLBACK_TO_TEMPLATE attribution. Step 6-7 cannot fail (template is deterministic).
 *
 * NOT @Singleton / NOT Hilt-injected: instantiated by model lifecycle code and registered
 * with ExplanationOrchestrator via setLlmEngine(). This allows runtime swap of models.
 */
class LocalLlmExplanationEngine(
    private val runtime: LlmRuntime,
    private val promptBuilder: PromptBuilder,
    private val slotParser: SlotParser,
    private val slotValidator: SlotValidator,
    private val templateEngine: TemplateExplanationEngine,
    private val policyGuard: PolicyGuard,
    private val inferenceConfig: InferenceConfig = InferenceConfig.SLOTS_DEFAULT
) : ExplanationEngine {

    override val engineId: String
        get() = "local-llm-${runtime.runtimeId}"

    override val isAvailable: Boolean
        get() = runtime.isAvailable

    /**
     * Explain the incident using the full LLM pipeline.
     *
     * On any failure → fallback to template engine.
     * The caller (ExplanationOrchestrator) has its own fallback too (defense in depth).
     */
    override fun explain(request: ExplanationRequest): ExplanationAnswer {
        val incident = request.incident

        // Step 1: PolicyGuard constraints
        val constraints = policyGuard.determineConstraints(incident)

        // Step 2: Build prompt
        val prompt = try {
            promptBuilder.buildPrompt(incident, constraints)
        } catch (e: Exception) {
            return fallbackWithAttribution(request, "Prompt build failed: ${e.message}")
        }

        // Step 3: Run inference
        val inferenceResult = try {
            runtime.runInference(prompt, inferenceConfig)
        } catch (e: Exception) {
            return fallbackWithAttribution(request, "Inference exception: ${e.message}")
        }

        if (!inferenceResult.success) {
            // C2-2.7: distinguish "busy" (single-flight contention) from real LLM errors.
            // Busy is NOT an error — it means another inference is running.
            val isBusy = inferenceResult.error?.contains("busy", ignoreCase = true) == true
            return fallbackWithAttribution(request, "Inference failed: ${inferenceResult.error}", isBusy)
        }

        // Step 4: Parse slots from raw output
        val parseResult = slotParser.parse(inferenceResult.rawOutput)
        if (!parseResult.isSuccess) {
            val error = (parseResult as ParseResult.Error).message
            return fallbackWithAttribution(request, "Parse failed: $error")
        }

        val rawSlots = parseResult.slotsOrNull!!

        // Step 5: Validate slots against incident
        val validationResult = slotValidator.validate(rawSlots, incident)
        if (!validationResult.isUsable) {
            val rejected = validationResult as ValidationResult.Rejected
            return fallbackWithAttribution(request, "Validation rejected: ${rejected.reason}")
        }

        val validatedSlots = validationResult.slotsOrNull!!

        // Step 6: Render via template engine (produces Czech text from slots)
        val answer = templateEngine.renderFromSlots(validatedSlots, incident)

        // Step 7: Final PolicyGuard validation (defense in depth — renderFromSlots does it too)
        return policyGuard.validate(answer, incident).copy(
            engineSource = EngineSource.LLM_ASSISTED
        )
    }

    /**
     * Fallback to template engine with LLM_FALLBACK_TO_TEMPLATE attribution.
     *
     * @param request The original request
     * @param reason Why the LLM path failed (for logging, NOT shown to user)
     * @param isBusy C2-2.7: true if fallback is due to single-flight contention (not an error)
     */
    private fun fallbackWithAttribution(
        request: ExplanationRequest,
        @Suppress("UNUSED_PARAMETER") reason: String,
        isBusy: Boolean = false
    ): ExplanationAnswer {
        // NOTE: Do NOT log `reason` in release builds (may contain prompt fragments).
        // Future: Write to internal diagnostics buffer only.
        return templateEngine.explain(request).copy(
            engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE,
            isBusyFallback = isBusy
        )
    }

    /**
     * Get diagnostics about the last inference (for debug self-test screen).
     */
    fun getDiagnostics(): EngineDiagnostics {
        return EngineDiagnostics(
            engineId = engineId,
            runtimeId = runtime.runtimeId,
            isAvailable = isAvailable,
            inferenceConfig = inferenceConfig
        )
    }

    /**
     * Shutdown runtime — release model memory. Safe to call multiple times.
     */
    fun shutdown() {
        runtime.shutdown()
    }
}

/**
 * Diagnostics snapshot for the debug UI.
 */
data class EngineDiagnostics(
    val engineId: String,
    val runtimeId: String,
    val isAvailable: Boolean,
    val inferenceConfig: InferenceConfig
)
