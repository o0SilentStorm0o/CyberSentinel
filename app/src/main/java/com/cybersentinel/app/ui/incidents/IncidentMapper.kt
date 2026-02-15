package com.cybersentinel.app.ui.incidents

import com.cybersentinel.app.data.local.SecurityEventEntity
import com.cybersentinel.app.domain.explainability.ExplanationAnswer
import com.cybersentinel.app.domain.security.*

/**
 * IncidentMapper — converts domain objects to UI presentation models.
 *
 * Pure functions, no side effects. Deterministic mapping.
 * Fully unit-testable without Android framework.
 */
object IncidentMapper {

    // ══════════════════════════════════════════════════════════
    //  Entity → Domain
    // ══════════════════════════════════════════════════════════

    /**
     * Convert a SecurityEventEntity (Room) back to a SecurityEvent (domain).
     * Signals are NOT reconstructed (they are transient) — we store only the event envelope.
     */
    fun toDomain(entity: SecurityEventEntity): SecurityEvent {
        return SecurityEvent(
            id = entity.id,
            startTime = entity.startTime,
            endTime = entity.endTime,
            source = try { SignalSource.valueOf(entity.source) } catch (_: Exception) { SignalSource.APP_SCANNER },
            type = try { EventType.valueOf(entity.eventType) } catch (_: Exception) { EventType.OTHER },
            severity = try { SignalSeverity.valueOf(entity.severity) } catch (_: Exception) { SignalSeverity.INFO },
            packageName = entity.packageName,
            summary = entity.summary,
            signals = emptyList(), // signals are transient
            metadata = parseMetadata(entity.metadata),
            isPromoted = entity.isPromoted
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Incident → Card Model
    // ══════════════════════════════════════════════════════════

    /**
     * Map a SecurityIncident to a list card model.
     * Shows max 2 packages with overflow indicator.
     */
    fun toCardModel(incident: SecurityIncident): IncidentCardModel {
        val displayPkgs = incident.affectedPackages.take(MAX_DISPLAY_PACKAGES)
        val threatPatterns = setOf("stalkerware", "dropper", "malware", "overlay", "spyware")
        val isThreat = incident.hypotheses.any { h ->
            threatPatterns.any { h.name.lowercase().contains(it) }
        }

        return IncidentCardModel(
            incidentId = incident.id,
            title = incident.title,
            shortSummary = incident.summary.take(MAX_SUMMARY_LENGTH).let {
                if (incident.summary.length > MAX_SUMMARY_LENGTH) "$it…" else it
            },
            severity = incident.severity,
            status = incident.status,
            displayPackages = displayPkgs,
            totalAffectedPackages = incident.affectedPackages.size,
            createdAt = incident.createdAt,
            isThreat = isThreat
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Incident + Explanation → Detail Model
    // ══════════════════════════════════════════════════════════

    /**
     * Map a SecurityIncident + ExplanationAnswer into the full detail model.
     * This is what the detail screen renders.
     */
    fun toDetailModel(
        incident: SecurityIncident,
        explanation: ExplanationAnswer
    ): IncidentDetailModel {
        val reasons = explanation.reasons.take(MAX_DISPLAY_REASONS).map { r ->
            ReasonUiModel(
                evidenceId = r.evidenceId,
                text = r.text,
                severity = r.severity,
                findingTag = r.findingTag,
                isHardEvidence = r.isHardEvidence
            )
        }

        val actions = explanation.actions.take(MAX_DISPLAY_ACTIONS).map { a ->
            ActionUiModel(
                stepNumber = a.stepNumber,
                title = a.title,
                description = a.description,
                actionCategory = a.actionCategory,
                targetPackage = a.targetPackage,
                isUrgent = a.isUrgent
            )
        }

        val techDetails = TechnicalDetailsModel(
            signals = incident.events.flatMap { e ->
                e.signals.map { s -> "[${s.severity}] ${s.source}: ${s.summary}" }
            }.ifEmpty {
                incident.events.map { e -> "[${e.severity}] ${e.source}: ${e.summary}" }
            },
            hypotheses = incident.hypotheses.map { h ->
                "${h.name} (${"%.0f".format(h.confidence * 100)}%)"
            },
            affectedPackages = incident.affectedPackages,
            metadata = incident.events.flatMap { e ->
                e.metadata.entries.map { it.key to it.value }
            }.toMap()
        )

        val engineLabel = when (explanation.engineSource) {
            com.cybersentinel.app.domain.explainability.EngineSource.TEMPLATE -> null
            com.cybersentinel.app.domain.explainability.EngineSource.LLM_ASSISTED -> "AI asistované"
            com.cybersentinel.app.domain.explainability.EngineSource.LLM_FALLBACK_TO_TEMPLATE -> "Šablonové (záloha)"
        }

        return IncidentDetailModel(
            incidentId = incident.id,
            title = incident.title,
            severity = incident.severity,
            status = incident.status,
            createdAt = incident.createdAt,
            whatHappened = explanation.summary,
            reasons = reasons,
            actions = actions,
            whenToIgnore = explanation.whenToIgnore,
            technicalDetails = techDetails,
            engineSourceLabel = engineLabel,
            isBusyFallback = explanation.isBusyFallback
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun parseMetadata(json: String?): Map<String, String> {
        if (json.isNullOrBlank()) return emptyMap()
        // Simple key=value parse; robust JSON parsing can come later
        return try {
            json.removeSurrounding("{", "}")
                .split(",")
                .mapNotNull { entry ->
                    val parts = entry.split(":", limit = 2)
                    if (parts.size == 2) {
                        parts[0].trim().removeSurrounding("\"") to
                            parts[1].trim().removeSurrounding("\"")
                    } else null
                }.toMap()
        } catch (_: Exception) {
            emptyMap()
        }
    }

    // ── Constants ──

    /** Max packages shown on the list card */
    const val MAX_DISPLAY_PACKAGES = 2
    /** Max summary characters on the list card */
    const val MAX_SUMMARY_LENGTH = 120
    /** Max evidence reasons on detail screen */
    const val MAX_DISPLAY_REASONS = 3
    /** Max action steps on detail screen */
    const val MAX_DISPLAY_ACTIONS = 3
}
