package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for the incident pipeline data models and RootCauseResolver.
 */
class SecurityIncidentTest {

    // ══════════════════════════════════════════════════════════
    //  SecuritySignal tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `signal has unique ID`() {
        val s1 = SecuritySignal(
            source = SignalSource.APP_SCANNER,
            type = SignalType.CERT_CHANGE,
            severity = SignalSeverity.HIGH,
            summary = "Cert changed"
        )
        val s2 = SecuritySignal(
            source = SignalSource.APP_SCANNER,
            type = SignalType.CERT_CHANGE,
            severity = SignalSeverity.HIGH,
            summary = "Cert changed"
        )
        assertNotEquals(s1.id, s2.id)
    }

    @Test
    fun `signal severity weights correct`() {
        assertEquals(40, SignalSeverity.CRITICAL.weight)
        assertEquals(25, SignalSeverity.HIGH.weight)
        assertEquals(15, SignalSeverity.MEDIUM.weight)
        assertEquals(5, SignalSeverity.LOW.weight)
        assertEquals(1, SignalSeverity.INFO.weight)
    }

    @Test
    fun `signal can carry metadata`() {
        val signal = SecuritySignal(
            source = SignalSource.CONFIG_BASELINE,
            type = SignalType.USER_CA_CERT_ADDED,
            severity = SignalSeverity.HIGH,
            summary = "User CA cert installed",
            details = mapOf("fingerprint" to "abc123", "issuer" to "Evil Corp")
        )
        assertEquals("abc123", signal.details["fingerprint"])
        assertEquals("Evil Corp", signal.details["issuer"])
    }

    // ══════════════════════════════════════════════════════════
    //  SecurityEvent tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `event has unique ID`() {
        val e1 = SecurityEvent(
            source = SignalSource.BASELINE,
            type = EventType.SUSPICIOUS_UPDATE,
            severity = SignalSeverity.HIGH,
            summary = "Update"
        )
        val e2 = SecurityEvent(
            source = SignalSource.BASELINE,
            type = EventType.SUSPICIOUS_UPDATE,
            severity = SignalSeverity.HIGH,
            summary = "Update"
        )
        assertNotEquals(e1.id, e2.id)
    }

    @Test
    fun `event can contain multiple signals`() {
        val signals = listOf(
            SecuritySignal(source = SignalSource.APP_SCANNER, type = SignalType.CERT_CHANGE, severity = SignalSeverity.HIGH, summary = "Cert change"),
            SecuritySignal(source = SignalSource.BASELINE, type = SignalType.INSTALLER_CHANGE, severity = SignalSeverity.MEDIUM, summary = "Installer change")
        )
        val event = SecurityEvent(
            source = SignalSource.BASELINE,
            type = EventType.SUSPICIOUS_UPDATE,
            severity = SignalSeverity.HIGH,
            summary = "Suspicious update",
            packageName = "com.example.app",
            signals = signals
        )
        assertEquals(2, event.signals.size)
    }

    // ══════════════════════════════════════════════════════════
    //  SecurityIncident tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `incident severity labels correct`() {
        assertEquals("Kritický", IncidentSeverity.CRITICAL.label)
        assertEquals("🔴", IncidentSeverity.CRITICAL.emoji)
        assertEquals("Vysoký", IncidentSeverity.HIGH.label)
        assertEquals("🟠", IncidentSeverity.HIGH.emoji)
    }

    @Test
    fun `incident status values`() {
        assertEquals(5, IncidentStatus.entries.size)
        assertTrue(IncidentStatus.entries.contains(IncidentStatus.FALSE_POSITIVE))
    }

    @Test
    fun `hypothesis confidence bounded`() {
        val hypothesis = Hypothesis(
            name = "Test",
            description = "Test hypothesis",
            confidence = 0.85,
            supportingEvidence = listOf("Evidence 1"),
            contradictingEvidence = listOf("Counter evidence")
        )
        assertTrue(hypothesis.confidence in 0.0..1.0)
    }

    // ══════════════════════════════════════════════════════════
    //  RootCauseResolver tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `resolver produces incident from stalkerware event`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.STALKERWARE_PATTERN,
            severity = SignalSeverity.CRITICAL,
            packageName = "com.evil.stalker",
            summary = "Stalkerware pattern detected"
        )

        val incident = resolver.resolve(event)

        assertEquals(IncidentSeverity.CRITICAL, incident.severity)
        assertTrue(incident.hypotheses.isNotEmpty())
        assertEquals("com.evil.stalker", incident.packageName)
        assertTrue(incident.hypotheses.first().name.contains("Stalkerware", ignoreCase = true))
    }

    @Test
    fun `resolver produces incident from dropper event`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.DROPPER_PATTERN,
            severity = SignalSeverity.CRITICAL,
            packageName = "com.evil.dropper",
            summary = "Dropper detected"
        )

        val incident = resolver.resolve(event)
        assertTrue(incident.hypotheses.any { it.name.contains("Dropper", ignoreCase = true) })
    }

    @Test
    fun `resolver produces dual hypotheses for suspicious update`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.BASELINE,
            type = EventType.SUSPICIOUS_UPDATE,
            severity = SignalSeverity.HIGH,
            packageName = "com.example.app",
            summary = "Suspicious update"
        )

        val incident = resolver.resolve(event)
        // Should have both "supply chain" and "legitimate update" hypotheses
        assertTrue(incident.hypotheses.size >= 2)
    }

    @Test
    fun `resolver hypotheses sorted by confidence descending`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.CAPABILITY_ESCALATION,
            severity = SignalSeverity.HIGH,
            packageName = "com.example.app",
            summary = "New permissions"
        )

        val incident = resolver.resolve(event)
        val confidences = incident.hypotheses.map { it.confidence }
        assertEquals(confidences, confidences.sortedDescending())
    }

    @Test
    fun `resolver always includes monitoring action`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.OTHER,
            severity = SignalSeverity.LOW,
            summary = "Generic event"
        )

        val incident = resolver.resolve(event)
        assertTrue(incident.recommendedActions.any { it.type == ActionCategory.MONITOR })
    }

    @Test
    fun `resolver boosts confidence with correlated events`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = EventType.STALKERWARE_PATTERN,
            severity = SignalSeverity.CRITICAL,
            packageName = "com.evil.app",
            summary = "Stalkerware"
        )
        val recentEvents = listOf(
            SecurityEvent(source = SignalSource.BASELINE, type = EventType.SUSPICIOUS_UPDATE, severity = SignalSeverity.HIGH, packageName = "com.evil.app", summary = "Update"),
            SecurityEvent(source = SignalSource.SPECIAL_ACCESS, type = EventType.SPECIAL_ACCESS_GRANT, severity = SignalSeverity.HIGH, packageName = "com.evil.app", summary = "Access")
        )

        val incidentWithCorrelation = resolver.resolve(event, recentEvents = recentEvents)
        val incidentWithout = resolver.resolve(event, recentEvents = emptyList())

        // Correlated events should boost confidence
        assertTrue(incidentWithCorrelation.hypotheses.first().confidence >= incidentWithout.hypotheses.first().confidence)
    }

    @Test
    fun `resolveAll groups events by package`() {
        val resolver = DefaultRootCauseResolver()
        val events = listOf(
            SecurityEvent(source = SignalSource.APP_SCANNER, type = EventType.STALKERWARE_PATTERN, severity = SignalSeverity.CRITICAL, packageName = "com.app1", summary = "A"),
            SecurityEvent(source = SignalSource.BASELINE, type = EventType.SUSPICIOUS_UPDATE, severity = SignalSeverity.HIGH, packageName = "com.app2", summary = "B")
        )

        val incidents = resolver.resolveAll(events)
        assertEquals(2, incidents.size)
    }

    @Test
    fun `CA cert event produces MITM and corporate hypotheses`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.CONFIG_BASELINE,
            type = EventType.CA_CERT_INSTALLED,
            severity = SignalSeverity.HIGH,
            summary = "CA cert installed"
        )

        val incident = resolver.resolve(event)
        assertTrue(incident.hypotheses.size >= 2)
        assertTrue(incident.hypotheses.any { it.name.contains("MITM", ignoreCase = true) || it.name.contains("odposlech", ignoreCase = true) })
        assertTrue(incident.hypotheses.any { it.name.contains("Firemní", ignoreCase = true) || it.name.contains("MDM", ignoreCase = true) })
    }

    @Test
    fun `config tamper event produces config hypothesis`() {
        val resolver = DefaultRootCauseResolver()
        val event = SecurityEvent(
            source = SignalSource.CONFIG_BASELINE,
            type = EventType.CONFIG_TAMPER,
            severity = SignalSeverity.MEDIUM,
            summary = "Config changed"
        )

        val incident = resolver.resolve(event)
        assertTrue(incident.hypotheses.isNotEmpty())
    }
}
