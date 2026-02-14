package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for SpecialAccessInspector data model and SpecialAccessSnapshot.
 *
 * Note: The actual system calls (Settings.Secure, DevicePolicyManager, etc.)
 * require Android context and are tested via instrumentation tests.
 * These tests verify the data model, query helpers, and snapshot behavior.
 */
class SpecialAccessInspectorTest {

    // ══════════════════════════════════════════════════════════
    //  SpecialAccessSnapshot data model tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `snapshot with no special access - hasAnySpecialAccess is false`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.app"
        )
        assertFalse(snapshot.hasAnySpecialAccess)
        assertEquals(0, snapshot.activeCount)
        assertTrue(snapshot.activeLabels.isEmpty())
    }

    @Test
    fun `snapshot with accessibility enabled - hasAnySpecialAccess is true`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.app",
            accessibilityEnabled = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(1, snapshot.activeCount)
        assertEquals(listOf("Usnadnění přístupu"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with notification listener enabled`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.app",
            notificationListenerEnabled = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(1, snapshot.activeCount)
        assertEquals(listOf("Čtení notifikací"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with device admin enabled`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.app",
            deviceAdminEnabled = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(1, snapshot.activeCount)
        assertEquals(listOf("Správce zařízení"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with multiple special access - all counted`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.stalker",
            accessibilityEnabled = true,
            notificationListenerEnabled = true,
            overlayEnabled = true,
            batteryOptimizationIgnored = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(4, snapshot.activeCount)
        assertEquals(
            listOf("Usnadnění přístupu", "Čtení notifikací", "Překrytí obrazovky", "Bez optimalizace baterie"),
            snapshot.activeLabels
        )
    }

    @Test
    fun `snapshot with all special access enabled`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.full",
            accessibilityEnabled = true,
            notificationListenerEnabled = true,
            deviceAdminEnabled = true,
            isDefaultSms = true,
            isDefaultDialer = true,
            overlayEnabled = true,
            batteryOptimizationIgnored = true
        )
        assertEquals(7, snapshot.activeCount)
        assertEquals(7, snapshot.activeLabels.size)
    }

    @Test
    fun `snapshot with default SMS - labels correct`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.sms",
            isDefaultSms = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(listOf("Výchozí SMS"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with default dialer - labels correct`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.dialer",
            isDefaultDialer = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(listOf("Výchozí telefon"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with overlay only`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.overlay",
            overlayEnabled = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(1, snapshot.activeCount)
        assertEquals(listOf("Překrytí obrazovky"), snapshot.activeLabels)
    }

    @Test
    fun `snapshot with battery optimization ignored only`() {
        val snapshot = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.battery",
            batteryOptimizationIgnored = true
        )
        assertTrue(snapshot.hasAnySpecialAccess)
        assertEquals(1, snapshot.activeCount)
        assertEquals(listOf("Bez optimalizace baterie"), snapshot.activeLabels)
    }
}
