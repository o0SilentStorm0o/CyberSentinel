package com.cybersentinel.app.ui.incidents

import com.cybersentinel.app.data.local.SecurityEventEntity
import com.cybersentinel.app.domain.explainability.ActionStep
import com.cybersentinel.app.domain.explainability.EngineSource
import com.cybersentinel.app.domain.explainability.EvidenceReason
import com.cybersentinel.app.domain.explainability.ExplanationAnswer
import com.cybersentinel.app.domain.security.*
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for the Sprint UI-1 incident presentation layer:
 *
 *  1. IncidentMapper — entity→domain, incident→card, incident+explanation→detail
 *  2. ActionIntentMapper — ActionCategory→Intent, Czech labels
 *  3. Sorting/overflow logic in UI models
 *
 * No Android framework required — all tested types are pure Kotlin.
 */
class IncidentUiLayerTest {

    // ══════════════════════════════════════════════════════════
    //  Test fixtures
    // ══════════════════════════════════════════════════════════

    private fun makeEntity(
        id: String = "evt-1",
        source: String = "APP_SCANNER",
        eventType: String = "SUSPICIOUS_UPDATE",
        severity: String = "HIGH",
        pkg: String? = "com.test.app",
        summary: String = "Cert changed",
        metadata: String? = null,
        isPromoted: Boolean = false
    ) = SecurityEventEntity(
        id = id,
        startTime = 1000L,
        endTime = null,
        source = source,
        eventType = eventType,
        severity = severity,
        packageName = pkg,
        summary = summary,
        signalIds = null,
        metadata = metadata,
        isPromoted = isPromoted
    )

    private fun makeIncident(
        id: String = "inc-1",
        severity: IncidentSeverity = IncidentSeverity.HIGH,
        status: IncidentStatus = IncidentStatus.OPEN,
        title: String = "Suspicious Update",
        summary: String = "App certificate changed unexpectedly",
        packages: List<String> = listOf("com.test.app"),
        hypotheses: List<Hypothesis> = listOf(
            Hypothesis(
                name = "Supply-chain compromise",
                description = "Cert changed without version bump",
                confidence = 0.7,
                supportingEvidence = listOf("cert-change-1")
            )
        ),
        actions: List<RecommendedAction> = listOf(
            RecommendedAction(
                priority = 1,
                type = ActionCategory.UNINSTALL,
                title = "Odinstalovat",
                description = "Remove the compromised app",
                targetPackage = "com.test.app"
            )
        ),
        createdAt: Long = 5000L
    ) = SecurityIncident(
        id = id,
        createdAt = createdAt,
        severity = severity,
        status = status,
        title = title,
        summary = summary,
        affectedPackages = packages,
        hypotheses = hypotheses,
        recommendedActions = actions
    )

    private fun makeAnswer(
        summary: String = "Certificate was replaced",
        reasons: List<EvidenceReason> = listOf(
            EvidenceReason("e1", "Certificate mismatch", IncidentSeverity.HIGH, "CERT_MISMATCH", true)
        ),
        actions: List<ActionStep> = listOf(
            ActionStep(1, ActionCategory.UNINSTALL, "Odinstalovat", "Remove the app", "com.test.app", true)
        ),
        whenToIgnore: String? = "When you changed the cert yourself",
        engineSource: EngineSource = EngineSource.TEMPLATE,
        isBusyFallback: Boolean = false
    ) = ExplanationAnswer(
        incidentId = "inc-1",
        severity = IncidentSeverity.HIGH,
        summary = summary,
        reasons = reasons,
        actions = actions,
        whenToIgnore = whenToIgnore,
        confidence = 0.8,
        engineSource = engineSource,
        isBusyFallback = isBusyFallback
    )

    // ══════════════════════════════════════════════════════════
    //  1. IncidentMapper.toDomain
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toDomain maps entity fields correctly`() {
        val entity = makeEntity()
        val event = IncidentMapper.toDomain(entity)

        assertEquals("evt-1", event.id)
        assertEquals(1000L, event.startTime)
        assertNull(event.endTime)
        assertEquals(SignalSource.APP_SCANNER, event.source)
        assertEquals(EventType.SUSPICIOUS_UPDATE, event.type)
        assertEquals(SignalSeverity.HIGH, event.severity)
        assertEquals("com.test.app", event.packageName)
        assertEquals("Cert changed", event.summary)
        assertTrue(event.signals.isEmpty())
        assertFalse(event.isPromoted)
    }

    @Test
    fun `toDomain fallback on invalid enum`() {
        val entity = makeEntity(source = "GARBAGE", eventType = "NONEXISTENT", severity = "UNKNOWN")
        val event = IncidentMapper.toDomain(entity)

        assertEquals(SignalSource.APP_SCANNER, event.source)
        assertEquals(EventType.OTHER, event.type)
        assertEquals(SignalSeverity.INFO, event.severity)
    }

    @Test
    fun `toDomain parses metadata JSON`() {
        val entity = makeEntity(metadata = """{"key1":"val1","key2":"val2"}""")
        val event = IncidentMapper.toDomain(entity)

        assertEquals(2, event.metadata.size)
        assertEquals("val1", event.metadata["key1"])
        assertEquals("val2", event.metadata["key2"])
    }

    @Test
    fun `toDomain handles null metadata`() {
        val entity = makeEntity(metadata = null)
        val event = IncidentMapper.toDomain(entity)
        assertTrue(event.metadata.isEmpty())
    }

    @Test
    fun `toDomain handles blank metadata`() {
        val entity = makeEntity(metadata = "  ")
        val event = IncidentMapper.toDomain(entity)
        assertTrue(event.metadata.isEmpty())
    }

    @Test
    fun `toDomain handles malformed metadata gracefully`() {
        val entity = makeEntity(metadata = "not json at all")
        val event = IncidentMapper.toDomain(entity)
        // Should not crash — may parse partial or empty
        assertNotNull(event.metadata)
    }

    // ══════════════════════════════════════════════════════════
    //  2. IncidentMapper.toCardModel
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toCardModel maps basic fields`() {
        val incident = makeIncident()
        val card = IncidentMapper.toCardModel(incident)

        assertEquals("inc-1", card.incidentId)
        assertEquals("Suspicious Update", card.title)
        assertEquals(IncidentSeverity.HIGH, card.severity)
        assertEquals(IncidentStatus.OPEN, card.status)
        assertEquals(5000L, card.createdAt)
    }

    @Test
    fun `toCardModel truncates summary at MAX_SUMMARY_LENGTH`() {
        val long = "A".repeat(200)
        val incident = makeIncident(summary = long)
        val card = IncidentMapper.toCardModel(incident)

        assertTrue(card.shortSummary.length <= IncidentMapper.MAX_SUMMARY_LENGTH + 1) // +1 for "…"
        assertTrue(card.shortSummary.endsWith("…"))
    }

    @Test
    fun `toCardModel does not truncate short summary`() {
        val incident = makeIncident(summary = "Short")
        val card = IncidentMapper.toCardModel(incident)

        assertEquals("Short", card.shortSummary)
        assertFalse(card.shortSummary.endsWith("…"))
    }

    @Test
    fun `toCardModel limits displayed packages to MAX_DISPLAY_PACKAGES`() {
        val incident = makeIncident(packages = listOf("a.b.c", "d.e.f", "g.h.i", "j.k.l"))
        val card = IncidentMapper.toCardModel(incident)

        assertEquals(IncidentMapper.MAX_DISPLAY_PACKAGES, card.displayPackages.size)
        assertEquals(4, card.totalAffectedPackages)
    }

    @Test
    fun `overflowLabel computed correctly`() {
        val incident = makeIncident(packages = listOf("a", "b", "c", "d"))
        val card = IncidentMapper.toCardModel(incident)

        assertEquals("+2", card.overflowLabel)
    }

    @Test
    fun `overflowLabel null when all packages fit`() {
        val incident = makeIncident(packages = listOf("a"))
        val card = IncidentMapper.toCardModel(incident)

        assertNull(card.overflowLabel)
    }

    @Test
    fun `toCardModel detects stalkerware threat via EventType`() {
        val incident = makeIncident(
            hypotheses = listOf(
                Hypothesis("Stalkerware detected", "desc", 0.9, listOf("e1"))
            )
        ).copy(
            events = listOf(
                SecurityEvent(
                    source = SignalSource.APP_SCANNER,
                    type = EventType.STALKERWARE_PATTERN,
                    severity = SignalSeverity.HIGH,
                    summary = "Stalkerware"
                )
            )
        )
        val card = IncidentMapper.toCardModel(incident)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardModel detects dropper threat via EventType`() {
        val incident = makeIncident(
            hypotheses = listOf(
                Hypothesis("Dropper pattern", "desc", 0.8, listOf("e1"))
            )
        ).copy(
            events = listOf(
                SecurityEvent(
                    source = SignalSource.APP_SCANNER,
                    type = EventType.DROPPER_PATTERN,
                    severity = SignalSeverity.HIGH,
                    summary = "Dropper"
                )
            )
        )
        val card = IncidentMapper.toCardModel(incident)
        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardModel non-threat for generic event type`() {
        val incident = makeIncident(
            hypotheses = listOf(
                Hypothesis("Config change", "desc", 0.5, listOf("e1"))
            )
        ).copy(
            events = listOf(
                SecurityEvent(
                    source = SignalSource.CONFIG_BASELINE,
                    type = EventType.CONFIG_TAMPER,
                    severity = SignalSeverity.MEDIUM,
                    summary = "Config changed"
                )
            )
        )
        val card = IncidentMapper.toCardModel(incident)
        assertFalse(card.isThreat)
    }

    @Test
    fun `toCardModel empty events is not threat`() {
        val incident = makeIncident(hypotheses = emptyList())
        val card = IncidentMapper.toCardModel(incident)
        assertFalse(card.isThreat)
    }

    // ══════════════════════════════════════════════════════════
    //  3. IncidentMapper.toDetailModel
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toDetailModel maps all 5 sections`() {
        val incident = makeIncident()
        val answer = makeAnswer()
        val detail = IncidentMapper.toDetailModel(incident, answer)

        assertEquals(incident.id, detail.incidentId)
        assertEquals("Certificate was replaced", detail.whatHappened)
        assertEquals(1, detail.reasons.size)
        assertEquals(1, detail.actions.size)
        assertEquals("When you changed the cert yourself", detail.whenToIgnore)
        assertNotNull(detail.technicalDetails)
    }

    @Test
    fun `toDetailModel limits reasons to MAX_DISPLAY_REASONS`() {
        val reasons = (1..5).map {
            EvidenceReason("e$it", "Reason $it", IncidentSeverity.HIGH, "TAG_$it", false)
        }
        val answer = makeAnswer(reasons = reasons)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)

        assertEquals(IncidentMapper.MAX_DISPLAY_REASONS, detail.reasons.size)
    }

    @Test
    fun `toDetailModel limits actions to MAX_DISPLAY_ACTIONS`() {
        val actions = (1..5).map {
            ActionStep(it, ActionCategory.CHECK_SETTINGS, "Action $it", "desc", null, false)
        }
        val answer = makeAnswer(actions = actions)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)

        assertEquals(IncidentMapper.MAX_DISPLAY_ACTIONS, detail.actions.size)
    }

    @Test
    fun `toDetailModel engine label null for TEMPLATE`() {
        val answer = makeAnswer(engineSource = EngineSource.TEMPLATE)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)
        assertNull(detail.engineSourceLabel)
    }

    @Test
    fun `toDetailModel engine label for LLM_ASSISTED`() {
        val answer = makeAnswer(engineSource = EngineSource.LLM_ASSISTED)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)
        assertEquals("AI asistované", detail.engineSourceLabel)
    }

    @Test
    fun `toDetailModel engine label for LLM_FALLBACK_TO_TEMPLATE`() {
        val answer = makeAnswer(engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)
        assertEquals("Šablonové (záloha)", detail.engineSourceLabel)
    }

    @Test
    fun `toDetailModel propagates isBusyFallback`() {
        val answer = makeAnswer(isBusyFallback = true)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)
        assertTrue(detail.isBusyFallback)
    }

    @Test
    fun `toDetailModel technicalDetails includes hypotheses`() {
        val incident = makeIncident()
        val answer = makeAnswer()
        val detail = IncidentMapper.toDetailModel(incident, answer)

        assertTrue(detail.technicalDetails.hypotheses.isNotEmpty())
        assertTrue(detail.technicalDetails.hypotheses[0].contains("Supply-chain"))
    }

    @Test
    fun `toDetailModel technicalDetails includes affected packages`() {
        val incident = makeIncident(packages = listOf("com.a", "com.b"))
        val answer = makeAnswer()
        val detail = IncidentMapper.toDetailModel(incident, answer)

        assertEquals(listOf("com.a", "com.b"), detail.technicalDetails.affectedPackages)
    }

    // ══════════════════════════════════════════════════════════
    //  4. ActionIntentMapper (label + null-returning categories)
    //  Note: Intent-creation tests require Robolectric (androidTest)
    //  because android.content.Intent is a framework class.
    //  Here we test the pure-Kotlin logic only.
    // ══════════════════════════════════════════════════════════

    @Test
    fun `getActionLabel all categories have non-empty labels`() {
        ActionCategory.entries.forEach { cat ->
            val label = ActionIntentMapper.getActionLabel(cat)
            assertTrue("Label for $cat should be non-empty", label.isNotBlank())
        }
    }

    @Test
    fun `getActionLabel UNINSTALL returns Czech label`() {
        assertEquals("Odinstalovat", ActionIntentMapper.getActionLabel(ActionCategory.UNINSTALL))
    }

    @Test
    fun `getActionLabel DISABLE returns Czech label`() {
        assertEquals("Zakázat aplikaci", ActionIntentMapper.getActionLabel(ActionCategory.DISABLE))
    }

    @Test
    fun `getActionLabel REINSTALL_FROM_STORE returns Czech label`() {
        assertEquals("Přeinstalovat z obchodu", ActionIntentMapper.getActionLabel(ActionCategory.REINSTALL_FROM_STORE))
    }

    @Test
    fun `getActionLabel MONITOR returns Czech label`() {
        assertEquals("Sledovat", ActionIntentMapper.getActionLabel(ActionCategory.MONITOR))
    }

    @Test
    fun `getActionLabel INFORM returns Czech label`() {
        assertEquals("Informace", ActionIntentMapper.getActionLabel(ActionCategory.INFORM))
    }

    @Test
    fun `getActionLabel CHECK_SETTINGS returns Czech label`() {
        assertEquals("Otevřít nastavení", ActionIntentMapper.getActionLabel(ActionCategory.CHECK_SETTINGS))
    }

    @Test
    fun `getActionLabel REVOKE_PERMISSION returns Czech label`() {
        assertEquals("Zkontrolovat oprávnění", ActionIntentMapper.getActionLabel(ActionCategory.REVOKE_PERMISSION))
    }

    @Test
    fun `getActionLabel FACTORY_RESET returns Czech label`() {
        assertEquals("Nastavení zařízení", ActionIntentMapper.getActionLabel(ActionCategory.FACTORY_RESET))
    }

    // ══════════════════════════════════════════════════════════
    //  5. Sorting logic (same as IncidentListViewModel)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `cards sort by severity descending then createdAt descending`() {
        val cards = listOf(
            IncidentMapper.toCardModel(makeIncident(id = "a", severity = IncidentSeverity.LOW, createdAt = 1000)),
            IncidentMapper.toCardModel(makeIncident(id = "b", severity = IncidentSeverity.CRITICAL, createdAt = 500)),
            IncidentMapper.toCardModel(makeIncident(id = "c", severity = IncidentSeverity.HIGH, createdAt = 3000)),
            IncidentMapper.toCardModel(makeIncident(id = "d", severity = IncidentSeverity.CRITICAL, createdAt = 2000))
        )

        val sorted = cards.sortedWith(
            compareByDescending<IncidentCardModel> { severityOrder(it.severity) }
                .thenByDescending { it.createdAt }
        )

        assertEquals("d", sorted[0].incidentId) // CRITICAL, newer
        assertEquals("b", sorted[1].incidentId) // CRITICAL, older
        assertEquals("c", sorted[2].incidentId) // HIGH
        assertEquals("a", sorted[3].incidentId) // LOW
    }

    @Test
    fun `activeCount counts OPEN and INVESTIGATING only`() {
        val incidents = listOf(
            makeIncident(id = "1", status = IncidentStatus.OPEN),
            makeIncident(id = "2", status = IncidentStatus.INVESTIGATING),
            makeIncident(id = "3", status = IncidentStatus.RESOLVED),
            makeIncident(id = "4", status = IncidentStatus.DISMISSED),
            makeIncident(id = "5", status = IncidentStatus.FALSE_POSITIVE)
        )
        val cards = incidents.map { IncidentMapper.toCardModel(it) }
        val activeCount = cards.count {
            it.status == IncidentStatus.OPEN || it.status == IncidentStatus.INVESTIGATING
        }

        assertEquals(2, activeCount)
    }

    // ══════════════════════════════════════════════════════════
    //  6. Edge cases
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toCardModel with no packages`() {
        val incident = makeIncident(packages = emptyList())
        val card = IncidentMapper.toCardModel(incident)

        assertTrue(card.displayPackages.isEmpty())
        assertEquals(0, card.totalAffectedPackages)
        assertNull(card.overflowLabel)
    }

    @Test
    fun `toDetailModel with empty reasons and actions`() {
        val answer = makeAnswer(reasons = emptyList(), actions = emptyList(), whenToIgnore = null)
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)

        assertTrue(detail.reasons.isEmpty())
        assertTrue(detail.actions.isEmpty())
        assertNull(detail.whenToIgnore)
    }

    @Test
    fun `toDetailModel reason fields map correctly`() {
        val reason = EvidenceReason("ev-1", "Bad cert", IncidentSeverity.CRITICAL, "CERT_BAD", true)
        val answer = makeAnswer(reasons = listOf(reason))
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)

        val r = detail.reasons[0]
        assertEquals("ev-1", r.evidenceId)
        assertEquals("Bad cert", r.text)
        assertEquals(IncidentSeverity.CRITICAL, r.severity)
        assertEquals("CERT_BAD", r.findingTag)
        assertTrue(r.isHardEvidence)
    }

    @Test
    fun `toDetailModel action fields map correctly`() {
        val action = ActionStep(2, ActionCategory.DISABLE, "Zakázat", "Disable it", "com.x", false)
        val answer = makeAnswer(actions = listOf(action))
        val detail = IncidentMapper.toDetailModel(makeIncident(), answer)

        val a = detail.actions[0]
        assertEquals(2, a.stepNumber)
        assertEquals(ActionCategory.DISABLE, a.actionCategory)
        assertEquals("Zakázat", a.title)
        assertEquals("Disable it", a.description)
        assertEquals("com.x", a.targetPackage)
        assertFalse(a.isUrgent)
    }

    // ── Helper matching IncidentListViewModel's sorting ──

    private fun severityOrder(s: IncidentSeverity): Int = when (s) {
        IncidentSeverity.CRITICAL -> 4
        IncidentSeverity.HIGH -> 3
        IncidentSeverity.MEDIUM -> 2
        IncidentSeverity.LOW -> 1
        IncidentSeverity.INFO -> 0
    }
}
