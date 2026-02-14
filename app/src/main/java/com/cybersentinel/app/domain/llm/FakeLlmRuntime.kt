package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.SecurityIncident

/**
 * FakeLlmRuntime — deterministic fixture runtime for Sprint C2-1 E2E testing.
 *
 * Returns well-formed JSON that exercises the full pipeline:
 *   PromptBuilder → FakeLlmRuntime → SlotParser → SlotValidator → renderFromSlots → PolicyGuard
 *
 * Fixtures are deterministic per incident severity — makes tests predictable.
 * Simulates realistic timing (~50ms per call in fake mode).
 *
 * Design:
 *  - No real model. No JNI. No download. Pure Kotlin.
 *  - Extracts signal IDs from the prompt so reason_ids reference real evidence
 *  - Covers all severity levels with appropriate responses
 *  - Can simulate failures (error mode) for fallback testing
 */
open class FakeLlmRuntime(
    private val latencyMs: Long = 50L,
    private var forceError: Boolean = false,
    private var errorMessage: String = "Simulated inference failure"
) : LlmRuntime {

    override val isAvailable: Boolean get() = !forceError
    override val runtimeId: String = "FakeLlmRuntime-v1"

    /**
     * Enable error mode — all subsequent calls will return failure.
     * For testing fallback behavior.
     */
    fun setErrorMode(enabled: Boolean, message: String = "Simulated inference failure") {
        forceError = enabled
        errorMessage = message
    }

    open override fun runInference(prompt: String, config: InferenceConfig): InferenceResult {
        val startTime = System.currentTimeMillis()

        // Simulate processing time
        if (latencyMs > 0) {
            try {
                Thread.sleep(latencyMs)
            } catch (_: InterruptedException) {
                return InferenceResult.failure("Interrupted", System.currentTimeMillis() - startTime)
            }
        }

        // Error mode
        if (forceError) {
            return InferenceResult.failure(errorMessage, System.currentTimeMillis() - startTime)
        }

        // Timeout check
        val elapsed = System.currentTimeMillis() - startTime
        if (elapsed > config.timeoutMs) {
            return InferenceResult.failure("Timeout exceeded", elapsed)
        }

        // Generate deterministic fixture based on prompt content
        val jsonOutput = generateFixture(prompt)
        val totalTime = System.currentTimeMillis() - startTime

        return InferenceResult.success(
            rawOutput = jsonOutput,
            timeToFirstTokenMs = latencyMs / 2,
            totalTimeMs = totalTime,
            tokensGenerated = (jsonOutput.length / 4).coerceAtLeast(10)
        )
    }

    override fun shutdown() {
        // Nothing to clean up in fake mode
    }

    // ══════════════════════════════════════════════════════════
    //  Fixture generation
    // ══════════════════════════════════════════════════════════

    /**
     * Generate a deterministic JSON fixture based on prompt content.
     *
     * Extracts evidence_id values from the prompt to produce valid reason_ids.
     * Selects severity-appropriate actions and tone.
     */
    internal fun generateFixture(prompt: String): String {
        val evidenceIds = extractEvidenceIds(prompt)
        val severity = detectSeverity(prompt)

        val (tone, actions, canIgnore, ignoreKey) = when (severity) {
            IncidentSeverity.CRITICAL -> FixtureProfile(
                tone = "strict",
                actions = listOf(ActionCategory.UNINSTALL, ActionCategory.REVOKE_PERMISSION, ActionCategory.DISABLE),
                canIgnore = false,
                ignoreKey = null
            )
            IncidentSeverity.HIGH -> FixtureProfile(
                tone = "neutral",
                actions = listOf(ActionCategory.REVOKE_PERMISSION, ActionCategory.CHECK_SETTINGS, ActionCategory.MONITOR),
                canIgnore = false,
                ignoreKey = null
            )
            IncidentSeverity.MEDIUM -> FixtureProfile(
                tone = "neutral",
                actions = listOf(ActionCategory.CHECK_SETTINGS, ActionCategory.MONITOR),
                canIgnore = true,
                ignoreKey = "user_initiated_update"
            )
            IncidentSeverity.LOW -> FixtureProfile(
                tone = "calm",
                actions = listOf(ActionCategory.MONITOR, ActionCategory.INFORM),
                canIgnore = true,
                ignoreKey = "known_developer_tool"
            )
            IncidentSeverity.INFO -> FixtureProfile(
                tone = "calm",
                actions = listOf(ActionCategory.INFORM),
                canIgnore = true,
                ignoreKey = "power_user_sideload"
            )
        }

        val reasonIdsJson = evidenceIds.take(3).joinToString(", ") { "\"$it\"" }
        val actionsJson = actions.joinToString(", ") { "\"${it.name}\"" }
        val confidence = when (severity) {
            IncidentSeverity.CRITICAL -> 0.92
            IncidentSeverity.HIGH -> 0.85
            IncidentSeverity.MEDIUM -> 0.75
            IncidentSeverity.LOW -> 0.65
            IncidentSeverity.INFO -> 0.55
        }

        return buildString {
            append("{")
            append("\"assessed_severity\":\"${severity.name}\",")
            append("\"summary_tone\":\"$tone\",")
            append("\"reason_ids\":[$reasonIdsJson],")
            append("\"action_categories\":[$actionsJson],")
            append("\"confidence\":$confidence,")
            append("\"can_be_ignored\":$canIgnore,")
            if (ignoreKey != null) {
                append("\"ignore_reason_key\":\"$ignoreKey\",")
            } else {
                append("\"ignore_reason_key\":null,")
            }
            append("\"notes\":\"Fake LLM analysis for ${severity.name} incident.\"")
            append("}")
        }
    }

    /**
     * Extract evidence_id values from the prompt.
     * Looks for lines like "      - evidence_id: some-uuid-here"
     */
    internal fun extractEvidenceIds(prompt: String): List<String> {
        val regex = Regex("evidence_id:\\s*(\\S+)")
        return regex.findAll(prompt).map { it.groupValues[1] }.toList()
    }

    /**
     * Detect incident severity from the prompt.
     * Looks for "severity: CRITICAL" etc. in the INCIDENT section.
     */
    internal fun detectSeverity(prompt: String): IncidentSeverity {
        // Look for the first severity line after "INCIDENT:"
        val regex = Regex("severity:\\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)", RegexOption.IGNORE_CASE)
        val match = regex.find(prompt)
        return match?.groupValues?.get(1)?.let {
            try { IncidentSeverity.valueOf(it.uppercase()) } catch (_: Exception) { null }
        } ?: IncidentSeverity.MEDIUM
    }

    /**
     * Internal fixture profile for deterministic responses.
     */
    private data class FixtureProfile(
        val tone: String,
        val actions: List<ActionCategory>,
        val canIgnore: Boolean,
        val ignoreKey: String?
    )

    companion object {
        /**
         * Create a fixture that wraps JSON in markdown fences (for testing parser robustness).
         */
        fun createMarkdownWrapped(): FakeLlmRuntime {
            return object : FakeLlmRuntime(latencyMs = 10L) {
                override fun runInference(prompt: String, config: InferenceConfig): InferenceResult {
                    val base = super.runInference(prompt, config)
                    return if (base.success) {
                        base.copy(rawOutput = "```json\n${base.rawOutput}\n```")
                    } else base
                }
            }
        }
    }
}
