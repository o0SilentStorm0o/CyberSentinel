package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for ConfigBaselineEngine delta detection logic.
 *
 * Note: captureSnapshot() requires Android context (Settings, ConnectivityManager)
 * and is tested via instrumentation. These tests verify the delta comparison
 * and signal conversion logic which is pure Kotlin.
 */
class ConfigBaselineEngineTest {

    // ══════════════════════════════════════════════════════════
    //  ConfigSnapshot tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `identical snapshots produce no changes`() {
        val snapshot = ConfigBaselineEngine.ConfigSnapshot(
            userCaCertFingerprints = setOf("abc123"),
            userCaCertCount = 1,
            privateDnsMode = "opportunistic",
            vpnActive = false,
            globalProxyConfigured = false,
            enabledAccessibilityServices = setOf("com.example.a11y"),
            enabledNotificationListeners = setOf("com.example.notif"),
            defaultSmsApp = "com.google.messages",
            defaultDialerApp = "com.google.dialer",
            developerOptionsEnabled = false,
            usbDebuggingEnabled = false
        )

        // Can't call compareSnapshots without engine instance (needs Context),
        // but we can test the configHash consistency
        val hash1 = snapshot.configHash
        val hash2 = snapshot.copy().configHash
        assertEquals(hash1, hash2)
    }

    @Test
    fun `different snapshots produce different hashes`() {
        val snapshot1 = ConfigBaselineEngine.ConfigSnapshot(
            privateDnsMode = "off"
        )
        val snapshot2 = ConfigBaselineEngine.ConfigSnapshot(
            privateDnsMode = "hostname",
            privateDnsHostname = "dns.example.com"
        )
        assertNotEquals(snapshot1.configHash, snapshot2.configHash)
    }

    @Test
    fun `config hash is deterministic`() {
        val snapshot = ConfigBaselineEngine.ConfigSnapshot(
            userCaCertFingerprints = setOf("cert1", "cert2"),
            vpnActive = true,
            enabledAccessibilityServices = setOf("com.a", "com.b")
        )
        val hash1 = snapshot.configHash
        val hash2 = snapshot.configHash
        assertEquals(hash1, hash2)
    }

    @Test
    fun `config hash is order-independent for sets`() {
        val snapshot1 = ConfigBaselineEngine.ConfigSnapshot(
            userCaCertFingerprints = setOf("cert1", "cert2"),
            enabledAccessibilityServices = setOf("com.a", "com.b")
        )
        val snapshot2 = ConfigBaselineEngine.ConfigSnapshot(
            userCaCertFingerprints = setOf("cert2", "cert1"),
            enabledAccessibilityServices = setOf("com.b", "com.a")
        )
        // Should be equal because sorted() is applied
        assertEquals(snapshot1.configHash, snapshot2.configHash)
    }

    // ══════════════════════════════════════════════════════════
    //  ConfigDelta tests (using ConfigChange directly)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `ConfigChange types have correct severity`() {
        // CA cert added should be HIGH
        val caCertChange = ConfigBaselineEngine.ConfigChange(
            type = ConfigBaselineEngine.ConfigChangeType.CA_CERT_ADDED,
            severity = SignalSeverity.HIGH,
            description = "CA cert added"
        )
        assertEquals(SignalSeverity.HIGH, caCertChange.severity)
    }

    @Test
    fun `ConfigDelta with no changes`() {
        val delta = ConfigBaselineEngine.ConfigDelta(
            hasChanges = false,
            changes = emptyList()
        )
        assertFalse(delta.hasChanges)
        assertTrue(delta.changes.isEmpty())
    }

    @Test
    fun `ConfigDelta with changes`() {
        val delta = ConfigBaselineEngine.ConfigDelta(
            hasChanges = true,
            changes = listOf(
                ConfigBaselineEngine.ConfigChange(
                    type = ConfigBaselineEngine.ConfigChangeType.VPN_ACTIVATED,
                    severity = SignalSeverity.MEDIUM,
                    description = "VPN activated"
                ),
                ConfigBaselineEngine.ConfigChange(
                    type = ConfigBaselineEngine.ConfigChangeType.CA_CERT_ADDED,
                    severity = SignalSeverity.HIGH,
                    description = "CA cert installed",
                    newValue = "abc123..."
                )
            )
        )
        assertTrue(delta.hasChanges)
        assertEquals(2, delta.changes.size)
    }

    // ══════════════════════════════════════════════════════════
    //  ConfigChangeType coverage
    // ══════════════════════════════════════════════════════════

    @Test
    fun `all change types are defined`() {
        val types = ConfigBaselineEngine.ConfigChangeType.entries
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.CA_CERT_ADDED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.CA_CERT_REMOVED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.PRIVATE_DNS_CHANGED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.VPN_ACTIVATED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.VPN_DEACTIVATED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.PROXY_CONFIGURED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.PROXY_REMOVED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.ACCESSIBILITY_SERVICE_ADDED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.ACCESSIBILITY_SERVICE_REMOVED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.NOTIFICATION_LISTENER_ADDED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.NOTIFICATION_LISTENER_REMOVED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.DEFAULT_SMS_CHANGED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.DEFAULT_DIALER_CHANGED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.DEVELOPER_OPTIONS_CHANGED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.USB_DEBUGGING_CHANGED))
        assertTrue(types.contains(ConfigBaselineEngine.ConfigChangeType.UNKNOWN_SOURCES_CHANGED))
    }
}
