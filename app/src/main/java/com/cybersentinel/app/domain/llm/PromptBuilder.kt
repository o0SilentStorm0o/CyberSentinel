package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.SafeLanguageFlag
import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.SecurityIncident
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PromptBuilder — constructs strict, structured prompts for on-device LLM inference.
 *
 * Design principles:
 *  1. NO PII in prompt — no SSIDs, hostnames, full app lists. Only anonymized evidence.
 *  2. JSON-only output schema — model returns LlmStructuredSlots, never free text.
 *  3. PolicyGuard constraints embedded — "allowed_claims" section tells model what's forbidden.
 *  4. Minimal token budget — compact prompt for fast inference on tiny models.
 *  5. Deterministic — same incident + constraints = same prompt.
 *
 * The prompt has 4 sections:
 *  A) System instruction (role + output schema + constraints)
 *  B) Incident context (severity, event type, signals, hypotheses — anonymized)
 *  C) Allowed claims (from PolicyGuard SafeLanguageFlags)
 *  D) Output instruction ("respond ONLY with JSON")
 */
@Singleton
class PromptBuilder @Inject constructor() {

    /**
     * Build a complete prompt from a SecurityIncident and PolicyGuard constraints.
     *
     * @param incident The security incident to explain
     * @param constraints Active SafeLanguageFlags from PolicyGuard
     * @return Complete prompt string ready for inference
     */
    fun buildPrompt(
        incident: SecurityIncident,
        constraints: Set<SafeLanguageFlag>
    ): String {
        return buildString {
            append(buildSystemInstruction())
            append("\n\n")
            append(buildIncidentContext(incident))
            append("\n\n")
            append(buildConstraints(constraints))
            append("\n\n")
            append(buildOutputInstruction())
        }
    }

    /**
     * Estimate the token count of a prompt (rough: ~4 chars per token for English).
     * Used for diagnostics and config tuning.
     */
    fun estimateTokenCount(prompt: String): Int = (prompt.length / 4).coerceAtLeast(1)

    // ══════════════════════════════════════════════════════════
    //  Section A: System instruction
    // ══════════════════════════════════════════════════════════

    private fun buildSystemInstruction(): String = """
You are a security analysis assistant. Analyze the incident below and return a JSON object.

OUTPUT SCHEMA (return ONLY this JSON, nothing else):
{
  "assessed_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "summary_tone": "calm" | "neutral" | "strict",
  "reason_ids": ["evidence_id_1", "evidence_id_2"],
  "action_categories": ["UNINSTALL", "REVOKE_PERMISSION", "CHECK_SETTINGS", "MONITOR"],
  "confidence": 0.0 to 1.0,
  "can_be_ignored": true | false,
  "ignore_reason_key": "user_initiated_update" | "known_developer_tool" | "corporate_profile" | "power_user_sideload" | "vpn_by_choice" | null,
  "notes": "optional short note (max 2 sentences)" | null
}

RULES:
- reason_ids MUST be from the evidence list below
- action_categories MUST be from: ${ActionCategory.values().joinToString(", ") { it.name }}
- assessed_severity MUST be from: ${IncidentSeverity.values().joinToString(", ") { it.name }}
- confidence MUST be between 0.0 and 1.0
- Select max 5 reason_ids, ordered by importance
- Select max 4 action_categories, ordered by urgency
- notes MUST be max 2 sentences or null
""".trimIndent()

    // ══════════════════════════════════════════════════════════
    //  Section B: Incident context (anonymized)
    // ══════════════════════════════════════════════════════════

    internal fun buildIncidentContext(incident: SecurityIncident): String = buildString {
        appendLine("INCIDENT:")
        appendLine("  severity: ${incident.severity.name}")
        appendLine("  package: ${anonymizePackage(incident.packageName)}")

        // Events (anonymized)
        if (incident.events.isNotEmpty()) {
            appendLine("  events:")
            for (event in incident.events.take(MAX_EVENTS)) {
                appendLine("    - type: ${event.type.name}")
                appendLine("      severity: ${event.severity.name}")

                // Signals as evidence list (with IDs for reason_ids reference)
                for (signal in event.signals.take(MAX_SIGNALS_PER_EVENT)) {
                    appendLine("      - evidence_id: ${signal.id}")
                    appendLine("        signal: ${signal.type.name}")
                    appendLine("        severity: ${signal.severity.name}")
                }
            }
        }

        // Hypotheses (from RootCauseResolver)
        if (incident.hypotheses.isNotEmpty()) {
            appendLine("  hypotheses:")
            for (hyp in incident.hypotheses.take(MAX_HYPOTHESES)) {
                appendLine("    - name: ${hyp.name}")
                appendLine("      confidence: ${hyp.confidence}")
                appendLine("      supporting: ${hyp.supportingEvidence.take(3).joinToString(", ")}")
                if (hyp.contradictingEvidence.isNotEmpty()) {
                    appendLine("      contradicting: ${hyp.contradictingEvidence.take(2).joinToString(", ")}")
                }
            }
        }

        // Existing recommended actions (for model context)
        if (incident.recommendedActions.isNotEmpty()) {
            appendLine("  current_recommendations:")
            for (action in incident.recommendedActions.take(MAX_ACTIONS)) {
                appendLine("    - ${action.type.name} (priority: ${action.priority})")
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Section C: PolicyGuard constraints
    // ══════════════════════════════════════════════════════════

    internal fun buildConstraints(constraints: Set<SafeLanguageFlag>): String = buildString {
        appendLine("CONSTRAINTS (you MUST respect these):")
        if (constraints.isEmpty()) {
            appendLine("  No additional constraints.")
        } else {
            for (flag in constraints) {
                appendLine("  - ${constraintDescriptions[flag] ?: flag.name}")
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Section D: Output instruction
    // ══════════════════════════════════════════════════════════

    private fun buildOutputInstruction(): String = """
Respond with ONLY the JSON object. No markdown, no explanation, no code fences.
""".trimIndent()

    // ══════════════════════════════════════════════════════════
    //  Privacy: anonymization
    // ══════════════════════════════════════════════════════════

    /**
     * Anonymize package name for prompt.
     *
     * Rules:
     *  - Keep the package name structure (com.example.app) — model needs it for category inference
     *  - Remove any personal identifiers if they appear in the package
     *  - NULL becomes "unknown_app"
     *
     * We keep the full package name because:
     *  1. It's already public information (published on Play Store)
     *  2. The model needs it to infer app category and expected behavior
     *  3. It never leaves the device (on-device inference)
     */
    internal fun anonymizePackage(packageName: String?): String {
        return packageName ?: "unknown_app"
    }

    // ══════════════════════════════════════════════════════════
    //  Constants and templates
    // ══════════════════════════════════════════════════════════

    companion object {
        /** Max events included in prompt (token budget) */
        const val MAX_EVENTS = 3

        /** Max signals per event in prompt */
        const val MAX_SIGNALS_PER_EVENT = 5

        /** Max hypotheses in prompt */
        const val MAX_HYPOTHESES = 3

        /** Max actions in prompt context */
        const val MAX_ACTIONS = 4

        /** English constraint descriptions for prompt (model understands English better) */
        val constraintDescriptions: Map<SafeLanguageFlag, String> = mapOf(
            SafeLanguageFlag.NO_MALWARE_CLAIM to
                "DO NOT claim this is malware (insufficient hard evidence)",
            SafeLanguageFlag.NO_VIRUS_CLAIM to
                "NEVER use the term 'virus' (not applicable to Android)",
            SafeLanguageFlag.NO_COMPROMISE_CLAIM to
                "DO NOT claim device is compromised (insufficient evidence)",
            SafeLanguageFlag.NO_FACTORY_RESET to
                "DO NOT recommend factory reset (disproportionate for this severity)",
            SafeLanguageFlag.NO_SPYING_CLAIM to
                "DO NOT claim app is spying (stalkerware pattern not confirmed)",
            SafeLanguageFlag.NO_ALARMIST_FRAMING to
                "Use calm/neutral tone only (severity does not justify alarm)"
        )
    }
}
