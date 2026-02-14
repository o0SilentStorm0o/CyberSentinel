package com.cybersentinel.app.domain.explainability

/**
 * ExplanationEngine — unified interface for producing user-facing explanations.
 *
 * Implementations:
 *  1. TemplateExplanationEngine — deterministic Czech templates (Sprint A, baseline)
 *  2. LlmExplanationEngine — LLM fills structured slots → template renders Czech (Sprint C)
 *
 * Contract:
 *  - Input: ExplanationRequest (incident + optional app knowledge + locale)
 *  - Output: ExplanationAnswer (structured, auditable, policy-validated)
 *  - Every implementation MUST apply PolicyGuard before returning
 *  - Every implementation MUST produce the same ExplanationAnswer schema
 *  - No raw LLM text in the output — only structured slots rendered by templates
 *
 * Thread safety: Implementations must be safe to call from coroutines.
 */
interface ExplanationEngine {

    /**
     * Produce a structured explanation for the given incident.
     *
     * @param request The explanation request containing incident + context
     * @return Structured, policy-validated explanation
     */
    fun explain(request: ExplanationRequest): ExplanationAnswer

    /**
     * Engine identifier for logging and quality tracking.
     */
    val engineId: String

    /**
     * Whether this engine is currently available and operational.
     * For TemplateEngine this is always true.
     * For LLM engine this depends on model availability + device capability + kill switch.
     */
    val isAvailable: Boolean
        get() = true
}
