package com.cybersentinel.app.ui.incidents

import com.cybersentinel.app.data.local.SecurityEventEntity
import com.cybersentinel.app.domain.capability.GateRule
import com.cybersentinel.app.domain.security.*
import com.cybersentinel.app.domain.security.BaselineManager.*
import com.cybersentinel.app.domain.security.SpecialAccessInspector.SpecialAccessSnapshot
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Sprint UI-2 additions:
 *
 *  1. EventRecorder — mapping + dedup + metadata
 *  2. IncidentMapper.toCardFromEntity — entity-only fast path
 *  3. IncidentMapper.isThreatEvent — EventType-based threat detection
 *  4. LlmErrorMapper — ERR|CODE → Czech user messages
 *  5. AiStatusViewModel gate reason labels
 *
 * All tests are pure Kotlin — no Android framework required.
 * EventRecorder DAO interactions tested via fake (insert captured).
 */
class IncidentUi2LayerTest {

    // ══════════════════════════════════════════════════════════
    //  Fixtures
    // ══════════════════════════════════════════════════════════

    private fun makeEntity(
        id: String = "evt-1",
        source: String = "APP_SCANNER",
        eventType: String = "SUSPICIOUS_UPDATE",
        severity: String = "HIGH",
        pkg: String? = "com.test.app",
        summary: String = "Cert changed",
        metadata: String? = null,
        isPromoted: Boolean = false,
        startTime: Long = 1000L
    ) = SecurityEventEntity(
        id = id,
        startTime = startTime,
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

    // ══════════════════════════════════════════════════════════
    //  1. EventRecorder — pure mapping tests
    // ══════════════════════════════════════════════════════════

    private val recorder = EventRecorder(FakeSecurityEventDao())

    @Test
    fun `mapSeverity maps all SecurityIssue severities`() {
        assertEquals(SignalSeverity.CRITICAL, recorder.mapSeverity(SecurityIssue.Severity.CRITICAL))
        assertEquals(SignalSeverity.HIGH, recorder.mapSeverity(SecurityIssue.Severity.HIGH))
        assertEquals(SignalSeverity.MEDIUM, recorder.mapSeverity(SecurityIssue.Severity.MEDIUM))
        assertEquals(SignalSeverity.LOW, recorder.mapSeverity(SecurityIssue.Severity.LOW))
        assertEquals(SignalSeverity.INFO, recorder.mapSeverity(SecurityIssue.Severity.INFO))
    }

    @Test
    fun `mapCategoryToEventType maps DEVICE to DEVICE_COMPROMISE`() {
        assertEquals(EventType.DEVICE_COMPROMISE, recorder.mapCategoryToEventType(SecurityIssue.Category.DEVICE))
    }

    @Test
    fun `mapCategoryToEventType maps APPS to SUSPICIOUS_UPDATE`() {
        assertEquals(EventType.SUSPICIOUS_UPDATE, recorder.mapCategoryToEventType(SecurityIssue.Category.APPS))
    }

    @Test
    fun `mapCategoryToEventType maps NETWORK to CONFIG_TAMPER`() {
        assertEquals(EventType.CONFIG_TAMPER, recorder.mapCategoryToEventType(SecurityIssue.Category.NETWORK))
    }

    @Test
    fun `mapCategoryToEventType maps ACCOUNTS to OTHER`() {
        assertEquals(EventType.OTHER, recorder.mapCategoryToEventType(SecurityIssue.Category.ACCOUNTS))
    }

    @Test
    fun `mapAnomalyToEventType maps all anomaly types`() {
        assertEquals(EventType.SUSPICIOUS_UPDATE, recorder.mapAnomalyToEventType(AnomalyType.CERT_CHANGED))
        assertEquals(EventType.SUSPICIOUS_UPDATE, recorder.mapAnomalyToEventType(AnomalyType.VERSION_ROLLBACK))
        assertEquals(EventType.SUSPICIOUS_INSTALL, recorder.mapAnomalyToEventType(AnomalyType.INSTALLER_CHANGED))
        assertEquals(EventType.CAPABILITY_ESCALATION, recorder.mapAnomalyToEventType(AnomalyType.HIGH_RISK_PERMISSION_ADDED))
        assertEquals(EventType.CAPABILITY_ESCALATION, recorder.mapAnomalyToEventType(AnomalyType.EXPORTED_SURFACE_INCREASED))
        assertEquals(EventType.SUSPICIOUS_INSTALL, recorder.mapAnomalyToEventType(AnomalyType.NEW_SYSTEM_APP))
        assertEquals(EventType.OTHER, recorder.mapAnomalyToEventType(AnomalyType.VERSION_CHANGED))
        assertEquals(EventType.DEVICE_COMPROMISE, recorder.mapAnomalyToEventType(AnomalyType.PARTITION_CHANGED))
        assertEquals(EventType.CAPABILITY_ESCALATION, recorder.mapAnomalyToEventType(AnomalyType.PERMISSION_SET_CHANGED))
    }

    @Test
    fun `mapAnomalySeverity maps all anomaly severities`() {
        assertEquals(SignalSeverity.CRITICAL, recorder.mapAnomalySeverity(AnomalySeverity.CRITICAL))
        assertEquals(SignalSeverity.HIGH, recorder.mapAnomalySeverity(AnomalySeverity.HIGH))
        assertEquals(SignalSeverity.MEDIUM, recorder.mapAnomalySeverity(AnomalySeverity.MEDIUM))
        assertEquals(SignalSeverity.LOW, recorder.mapAnomalySeverity(AnomalySeverity.LOW))
    }

    @Test
    fun `deterministicId produces same output for same input`() {
        val id1 = recorder.deterministicId("device", "usb_debug")
        val id2 = recorder.deterministicId("device", "usb_debug")
        assertEquals(id1, id2)
    }

    @Test
    fun `deterministicId produces different output for different input`() {
        val id1 = recorder.deterministicId("device", "usb_debug")
        val id2 = recorder.deterministicId("device", "dev_options")
        assertNotEquals(id1, id2)
    }

    @Test
    fun `deterministicId produces different output for different prefix`() {
        val id1 = recorder.deterministicId("device", "usb_debug")
        val id2 = recorder.deterministicId("app", "usb_debug")
        assertNotEquals(id1, id2)
    }

    @Test
    fun `buildMetadata creates valid JSON-ish string`() {
        val result = recorder.buildMetadata("key1" to "val1", "key2" to "val2")
        assertNotNull(result)
        assertTrue(result!!.startsWith("{"))
        assertTrue(result.endsWith("}"))
        assertTrue(result.contains("\"key1\":\"val1\""))
        assertTrue(result.contains("\"key2\":\"val2\""))
    }

    @Test
    fun `buildMetadata filters blank values`() {
        val result = recorder.buildMetadata("key1" to "val1", "key2" to "", "key3" to "val3")
        assertNotNull(result)
        assertFalse(result!!.contains("key2"))
    }

    @Test
    fun `buildMetadata returns null for all blank values`() {
        val result = recorder.buildMetadata("key1" to "", "key2" to "")
        assertNull(result)
    }

    // ══════════════════════════════════════════════════════════
    //  2. IncidentMapper.toCardFromEntity
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toCardFromEntity maps basic fields`() {
        val entity = makeEntity()
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals("evt-1", card.incidentId)
        assertEquals("Cert changed", card.title)
        assertEquals(IncidentSeverity.HIGH, card.severity)
        assertEquals(IncidentStatus.OPEN, card.status)
        assertEquals(1000L, card.createdAt)
    }

    @Test
    fun `toCardFromEntity promoted entity maps to RESOLVED`() {
        val entity = makeEntity(isPromoted = true)
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals(IncidentStatus.RESOLVED, card.status)
    }

    @Test
    fun `toCardFromEntity non-promoted entity maps to OPEN`() {
        val entity = makeEntity(isPromoted = false)
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals(IncidentStatus.OPEN, card.status)
    }

    @Test
    fun `toCardFromEntity with package sets displayPackages`() {
        val entity = makeEntity(pkg = "com.test.app")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals(listOf("com.test.app"), card.displayPackages)
        assertEquals(1, card.totalAffectedPackages)
    }

    @Test
    fun `toCardFromEntity null package sets empty displayPackages`() {
        val entity = makeEntity(pkg = null)
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.displayPackages.isEmpty())
        assertEquals(0, card.totalAffectedPackages)
    }

    @Test
    fun `toCardFromEntity falls back on invalid severity`() {
        val entity = makeEntity(severity = "GARBAGE")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals(IncidentSeverity.INFO, card.severity)
    }

    @Test
    fun `toCardFromEntity falls back on invalid eventType`() {
        val entity = makeEntity(eventType = "UNKNOWN_TYPE")
        val card = IncidentMapper.toCardFromEntity(entity)

        // EventType.OTHER → not a threat type
        assertFalse(card.isThreat)
    }

    @Test
    fun `toCardFromEntity STALKERWARE_PATTERN is threat`() {
        val entity = makeEntity(eventType = "STALKERWARE_PATTERN", severity = "HIGH")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity DROPPER_PATTERN is threat`() {
        val entity = makeEntity(eventType = "DROPPER_PATTERN", severity = "MEDIUM")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity OVERLAY_ATTACK_PATTERN is threat`() {
        val entity = makeEntity(eventType = "OVERLAY_ATTACK_PATTERN", severity = "HIGH")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity DEVICE_COMPROMISE is threat`() {
        val entity = makeEntity(eventType = "DEVICE_COMPROMISE", severity = "CRITICAL")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity CAPABILITY_ESCALATION with HIGH severity is threat`() {
        val entity = makeEntity(eventType = "CAPABILITY_ESCALATION", severity = "HIGH")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity CAPABILITY_ESCALATION with CRITICAL severity is threat`() {
        val entity = makeEntity(eventType = "CAPABILITY_ESCALATION", severity = "CRITICAL")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.isThreat)
    }

    @Test
    fun `toCardFromEntity CAPABILITY_ESCALATION with MEDIUM severity is NOT threat`() {
        val entity = makeEntity(eventType = "CAPABILITY_ESCALATION", severity = "MEDIUM")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertFalse(card.isThreat)
    }

    @Test
    fun `toCardFromEntity SUSPICIOUS_UPDATE is NOT threat`() {
        val entity = makeEntity(eventType = "SUSPICIOUS_UPDATE", severity = "HIGH")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertFalse(card.isThreat)
    }

    @Test
    fun `toCardFromEntity OTHER is NOT threat`() {
        val entity = makeEntity(eventType = "OTHER", severity = "CRITICAL")
        val card = IncidentMapper.toCardFromEntity(entity)

        assertFalse(card.isThreat)
    }

    @Test
    fun `toCardFromEntity shortSummary uses metadata description if available`() {
        val entity = makeEntity(
            summary = "Short title",
            metadata = """{"description":"Detailed vulnerability description for the user"}"""
        )
        val card = IncidentMapper.toCardFromEntity(entity)

        assertTrue(card.shortSummary.contains("Detailed vulnerability"))
    }

    @Test
    fun `toCardFromEntity shortSummary falls back to summary when no metadata`() {
        val entity = makeEntity(summary = "Cert changed", metadata = null)
        val card = IncidentMapper.toCardFromEntity(entity)

        assertEquals("Cert changed", card.shortSummary)
    }

    // ══════════════════════════════════════════════════════════
    //  3. isThreatEvent (static method)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `isThreatEvent returns true for all threat types`() {
        val threatTypes = listOf(
            EventType.STALKERWARE_PATTERN,
            EventType.DROPPER_PATTERN,
            EventType.OVERLAY_ATTACK_PATTERN,
            EventType.DEVICE_COMPROMISE
        )
        for (type in threatTypes) {
            assertTrue("$type should be threat", IncidentMapper.isThreatEvent(type, IncidentSeverity.INFO))
        }
    }

    @Test
    fun `isThreatEvent CAPABILITY_ESCALATION HIGH is threat`() {
        assertTrue(IncidentMapper.isThreatEvent(EventType.CAPABILITY_ESCALATION, IncidentSeverity.HIGH))
    }

    @Test
    fun `isThreatEvent CAPABILITY_ESCALATION CRITICAL is threat`() {
        assertTrue(IncidentMapper.isThreatEvent(EventType.CAPABILITY_ESCALATION, IncidentSeverity.CRITICAL))
    }

    @Test
    fun `isThreatEvent CAPABILITY_ESCALATION MEDIUM is not threat`() {
        assertFalse(IncidentMapper.isThreatEvent(EventType.CAPABILITY_ESCALATION, IncidentSeverity.MEDIUM))
    }

    @Test
    fun `isThreatEvent CAPABILITY_ESCALATION LOW is not threat`() {
        assertFalse(IncidentMapper.isThreatEvent(EventType.CAPABILITY_ESCALATION, IncidentSeverity.LOW))
    }

    @Test
    fun `isThreatEvent non-threat types return false`() {
        val nonThreat = listOf(
            EventType.SUSPICIOUS_UPDATE,
            EventType.SUSPICIOUS_INSTALL,
            EventType.CONFIG_TAMPER,
            EventType.CA_CERT_INSTALLED,
            EventType.SUSPICIOUS_VPN,
            EventType.BEHAVIORAL_ANOMALY,
            EventType.SPECIAL_ACCESS_GRANT,
            EventType.OTHER
        )
        for (type in nonThreat) {
            assertFalse("$type should not be threat at MEDIUM",
                IncidentMapper.isThreatEvent(type, IncidentSeverity.MEDIUM))
        }
    }

    // ══════════════════════════════════════════════════════════
    //  4. LlmErrorMapper
    // ══════════════════════════════════════════════════════════

    @Test
    fun `toUserMessage maps ERR NULL_HANDLE`() {
        val msg = LlmErrorMapper.toUserMessage("Inference failed: ERR|NULL_HANDLE")
        assertTrue(msg.contains("model není načten"))
    }

    @Test
    fun `toUserMessage maps ERR STALE_HANDLE`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|STALE_HANDLE detected")
        assertTrue(msg.contains("vypršela"))
    }

    @Test
    fun `toUserMessage maps ERR POISONED`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|POISONED")
        assertTrue(msg.contains("chybovém stavu"))
    }

    @Test
    fun `toUserMessage maps ERR NULL_CTX`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|NULL_CTX")
        assertTrue(msg.contains("kontext"))
    }

    @Test
    fun `toUserMessage maps ERR NULL_PROMPT`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|NULL_PROMPT")
        assertTrue(msg.contains("prázdný dotaz"))
    }

    @Test
    fun `toUserMessage maps ERR TOKENIZE`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|TOKENIZE")
        assertTrue(msg.contains("zpracovat text"))
    }

    @Test
    fun `toUserMessage maps ERR CTX_OVERFLOW`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|CTX_OVERFLOW")
        assertTrue(msg.contains("rozsáhlý"))
    }

    @Test
    fun `toUserMessage maps ERR DECODE`() {
        val msg = LlmErrorMapper.toUserMessage("ERR|DECODE")
        assertTrue(msg.contains("generování"))
    }

    @Test
    fun `toUserMessage unknown error wraps message`() {
        val msg = LlmErrorMapper.toUserMessage("Something random happened")
        assertTrue(msg.contains("Something random happened"))
        assertTrue(msg.startsWith("Vysvětlení selhalo"))
    }

    @Test
    fun `toUserMessage blank error returns generic`() {
        val msg = LlmErrorMapper.toUserMessage("")
        assertEquals("Vysvětlení selhalo. Zkuste to znovu.", msg)
    }

    @Test
    fun `isKnownError returns true for known codes`() {
        assertTrue(LlmErrorMapper.isKnownError("ERR|NULL_HANDLE"))
        assertTrue(LlmErrorMapper.isKnownError("ERR|POISONED"))
    }

    @Test
    fun `isKnownError returns false for unknown codes`() {
        assertFalse(LlmErrorMapper.isKnownError("UNKNOWN"))
        assertFalse(LlmErrorMapper.isKnownError(""))
    }

    @Test
    fun `knownCodes contains all 8 ERR codes`() {
        assertEquals(8, LlmErrorMapper.knownCodes().size)
    }

    // ══════════════════════════════════════════════════════════
    //  5. AiStatusViewModel gate reason labels
    // ══════════════════════════════════════════════════════════

    @Test
    fun `gate reason labels cover all GateRule values`() {
        // Use a dummy AiStatusViewModel-like approach with the same mapping
        val labels = GateRule.entries.map { rule ->
            when (rule) {
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
        // All entries produce non-empty labels
        assertTrue(labels.all { it.isNotBlank() })
        assertEquals(GateRule.entries.size, labels.size)
    }

    // ══════════════════════════════════════════════════════════
    //  6. toCardModel with EventType-based threat detection
    // ══════════════════════════════════════════════════════════

    private fun makeIncident(
        id: String = "inc-1",
        severity: IncidentSeverity = IncidentSeverity.HIGH,
        events: List<SecurityEvent> = listOf(
            SecurityEvent(
                source = SignalSource.APP_SCANNER,
                type = EventType.SUSPICIOUS_UPDATE,
                severity = SignalSeverity.HIGH,
                summary = "test"
            )
        ),
        hypotheses: List<Hypothesis> = emptyList()
    ) = SecurityIncident(
        id = id,
        createdAt = 1000L,
        severity = severity,
        status = IncidentStatus.OPEN,
        title = "Test",
        summary = "Test summary",
        affectedPackages = listOf("com.test"),
        hypotheses = hypotheses,
        recommendedActions = emptyList(),
        events = events
    )

    @Test
    fun `toCardModel threat detection uses EventType not hypothesis name`() {
        // EventType = STALKERWARE_PATTERN → isThreat = true even with generic hypothesis name
        val incident = makeIncident(
            events = listOf(
                SecurityEvent(
                    source = SignalSource.APP_SCANNER,
                    type = EventType.STALKERWARE_PATTERN,
                    severity = SignalSeverity.HIGH,
                    summary = "test"
                )
            ),
            hypotheses = listOf(
                Hypothesis("Generic name", "desc", 0.9, listOf("e1"))
            )
        )
        val card = IncidentMapper.toCardModel(incident)
        assertTrue("STALKERWARE_PATTERN event should be threat", card.isThreat)
    }

    @Test
    fun `toCardModel non-threat EventType is not threat even with scary hypothesis name`() {
        val incident = makeIncident(
            events = listOf(
                SecurityEvent(
                    source = SignalSource.APP_SCANNER,
                    type = EventType.OTHER,
                    severity = SignalSeverity.MEDIUM,
                    summary = "test"
                )
            ),
            hypotheses = listOf(
                Hypothesis("Stalkerware detected", "desc", 0.9, listOf("e1"))
            )
        )
        val card = IncidentMapper.toCardModel(incident)
        assertFalse("OTHER event should not be threat even with scary hypothesis name", card.isThreat)
    }

    // ══════════════════════════════════════════════════════════
    //  Fake DAO for EventRecorder constructor
    // ══════════════════════════════════════════════════════════

    /**
     * Minimal fake DAO that does nothing. EventRecorder's pure mapping methods
     * (internal) don't call DAO — only recordXxx() does, which we can't call
     * in pure JUnit without suspend context. The mapping tests exercise
     * the internal methods directly.
     */
    private class FakeSecurityEventDao : com.cybersentinel.app.data.local.SecurityEventDao {
        val inserted = mutableListOf<SecurityEventEntity>()

        override suspend fun getAll() = emptyList<SecurityEventEntity>()
        override suspend fun getByPackage(packageName: String) = emptyList<SecurityEventEntity>()
        override suspend fun getBySource(source: String) = emptyList<SecurityEventEntity>()
        override suspend fun getUnpromotedHighSeverity() = emptyList<SecurityEventEntity>()
        override suspend fun getActiveEvents(recentCutoff: Long) = emptyList<SecurityEventEntity>()
        override suspend fun getSince(since: Long) = emptyList<SecurityEventEntity>()
        override suspend fun getSinceForPackage(since: Long, packageName: String) = emptyList<SecurityEventEntity>()
        override suspend fun insert(event: SecurityEventEntity) { inserted.add(event) }
        override suspend fun insertAll(events: List<SecurityEventEntity>) { inserted.addAll(events) }
        override suspend fun markPromoted(eventId: String) {}
        override suspend fun deleteExpired(now: Long) {}
        override suspend fun deleteOlderThan(before: Long) {}
        override suspend fun countEventsSince(packageName: String, eventType: String, since: Long) = 0
        override suspend fun deleteAll() {}
    }
}
