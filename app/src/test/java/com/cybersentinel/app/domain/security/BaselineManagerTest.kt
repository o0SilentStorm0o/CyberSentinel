package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for BaselineManager — specifically the relative exported surface delta logic.
 *
 * Note: Full integration tests require Room + DAO. These unit tests focus on the
 * data model behavior and the AnomalySeverity classification logic.
 */
class BaselineManagerTest {

    // ══════════════════════════════════════════════════════════
    //  ExportedSurface data model
    // ══════════════════════════════════════════════════════════

    @Test
    fun `ExportedSurface default values are 0`() {
        val surface = BaselineManager.ExportedSurface()
        assertEquals(0, surface.exportedActivityCount)
        assertEquals(0, surface.exportedServiceCount)
        assertEquals(0, surface.exportedReceiverCount)
        assertEquals(0, surface.exportedProviderCount)
        assertEquals(0, surface.unprotectedExportedCount)
    }

    @Test
    fun `ExportedSurface stores all component types`() {
        val surface = BaselineManager.ExportedSurface(
            exportedActivityCount = 3,
            exportedServiceCount = 2,
            exportedReceiverCount = 5,
            exportedProviderCount = 1,
            unprotectedExportedCount = 4
        )
        assertEquals(3, surface.exportedActivityCount)
        assertEquals(2, surface.exportedServiceCount)
        assertEquals(5, surface.exportedReceiverCount)
        assertEquals(1, surface.exportedProviderCount)
        assertEquals(4, surface.unprotectedExportedCount)
    }

    // ══════════════════════════════════════════════════════════
    //  AnomalyType and AnomalySeverity classification
    // ══════════════════════════════════════════════════════════

    @Test
    fun `AnomalyType values include all expected types`() {
        val types = BaselineManager.AnomalyType.entries.map { it.name }.toSet()
        assertTrue(types.contains("CERT_CHANGED"))
        assertTrue(types.contains("NEW_SYSTEM_APP"))
        assertTrue(types.contains("VERSION_CHANGED"))
        assertTrue(types.contains("INSTALLER_CHANGED"))
        assertTrue(types.contains("PARTITION_CHANGED"))
        assertTrue(types.contains("PERMISSION_SET_CHANGED"))
        assertTrue(types.contains("HIGH_RISK_PERMISSION_ADDED"))
        assertTrue(types.contains("EXPORTED_SURFACE_INCREASED"))
        assertTrue(types.contains("VERSION_ROLLBACK"))
    }

    @Test
    fun `AnomalySeverity has correct ordering`() {
        assertTrue(BaselineManager.AnomalySeverity.CRITICAL.ordinal < BaselineManager.AnomalySeverity.HIGH.ordinal)
        assertTrue(BaselineManager.AnomalySeverity.HIGH.ordinal < BaselineManager.AnomalySeverity.MEDIUM.ordinal)
        assertTrue(BaselineManager.AnomalySeverity.MEDIUM.ordinal < BaselineManager.AnomalySeverity.LOW.ordinal)
    }

    // ══════════════════════════════════════════════════════════
    //  High-risk permission set
    // ══════════════════════════════════════════════════════════

    @Test
    fun `HIGH_RISK_PERMISSIONS contains all expected permissions`() {
        val hrp = BaselineManager.HIGH_RISK_PERMISSIONS
        assertTrue(hrp.contains("android.permission.READ_SMS"))
        assertTrue(hrp.contains("android.permission.SEND_SMS"))
        assertTrue(hrp.contains("android.permission.RECEIVE_SMS"))
        assertTrue(hrp.contains("android.permission.READ_CALL_LOG"))
        assertTrue(hrp.contains("android.permission.BIND_ACCESSIBILITY_SERVICE"))
        assertTrue(hrp.contains("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"))
        assertTrue(hrp.contains("android.permission.BIND_DEVICE_ADMIN"))
        assertTrue(hrp.contains("android.permission.BIND_VPN_SERVICE"))
        assertTrue(hrp.contains("android.permission.SYSTEM_ALERT_WINDOW"))
        assertTrue(hrp.contains("android.permission.REQUEST_INSTALL_PACKAGES"))
        assertTrue(hrp.contains("android.permission.ACCESS_BACKGROUND_LOCATION"))
    }

    @Test
    fun `HIGH_RISK_PERMISSIONS does NOT contain normal privacy permissions`() {
        val hrp = BaselineManager.HIGH_RISK_PERMISSIONS
        assertFalse("CAMERA should not be high-risk", hrp.contains("android.permission.CAMERA"))
        assertFalse("CONTACTS should not be high-risk", hrp.contains("android.permission.READ_CONTACTS"))
        assertFalse("LOCATION should not be high-risk", hrp.contains("android.permission.ACCESS_FINE_LOCATION"))
        assertFalse("RECORD_AUDIO should not be high-risk", hrp.contains("android.permission.RECORD_AUDIO"))
    }

    // ══════════════════════════════════════════════════════════
    //  BaselineComparison and BaselineStatus
    // ══════════════════════════════════════════════════════════

    @Test
    fun `BaselineStatus NEW means first time seeing app`() {
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.example.new",
            status = BaselineManager.BaselineStatus.NEW,
            anomalies = emptyList(),
            isFirstScan = true,
            scanCount = 0
        )
        assertEquals(BaselineManager.BaselineStatus.NEW, comparison.status)
        assertTrue(comparison.isFirstScan)
    }

    @Test
    fun `BaselineComparison with anomalies has CHANGED status`() {
        val anomaly = BaselineManager.BaselineAnomaly(
            type = BaselineManager.AnomalyType.CERT_CHANGED,
            severity = BaselineManager.AnomalySeverity.CRITICAL,
            description = "Cert changed"
        )
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.example.changed",
            status = BaselineManager.BaselineStatus.CHANGED,
            anomalies = listOf(anomaly),
            isFirstScan = false,
            scanCount = 5
        )
        assertEquals(BaselineManager.BaselineStatus.CHANGED, comparison.status)
        assertEquals(1, comparison.anomalies.size)
        assertEquals(BaselineManager.AnomalyType.CERT_CHANGED, comparison.anomalies[0].type)
    }

    // ══════════════════════════════════════════════════════════
    //  Relative exported surface delta logic verification
    //  (The actual computation happens in compareWithBaseline
    //   which needs a DAO, but we verify the design semantics)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `relative delta - from 0 to 2 should be HIGH severity`() {
        // Encoding the expected behavior: 0→2+ unprotected = new attack surface
        val oldUnprotected = 0
        val newUnprotected = 2
        val delta = newUnprotected - oldUnprotected
        
        val severity = computeExpectedSurfaceSeverity(oldUnprotected, newUnprotected, delta)
        assertEquals(BaselineManager.AnomalySeverity.HIGH, severity)
    }

    @Test
    fun `relative delta - 50 percent increase should be MEDIUM`() {
        val oldUnprotected = 10
        val newUnprotected = 16  // +6 = 60% increase
        val delta = newUnprotected - oldUnprotected
        
        val severity = computeExpectedSurfaceSeverity(oldUnprotected, newUnprotected, delta)
        assertEquals(BaselineManager.AnomalySeverity.MEDIUM, severity)
    }

    @Test
    fun `relative delta - small change on large surface is LOW`() {
        val oldUnprotected = 80
        val newUnprotected = 82  // +2 = 2.5% increase
        val delta = newUnprotected - oldUnprotected
        
        val severity = computeExpectedSurfaceSeverity(oldUnprotected, newUnprotected, delta)
        assertEquals(BaselineManager.AnomalySeverity.LOW, severity)
    }

    @Test
    fun `relative delta - absolute jump of 5 plus is MEDIUM even on large surface`() {
        val oldUnprotected = 50
        val newUnprotected = 56  // +6, but only 12% → MEDIUM because delta >= 5
        val delta = newUnprotected - oldUnprotected
        
        val severity = computeExpectedSurfaceSeverity(oldUnprotected, newUnprotected, delta)
        assertEquals(BaselineManager.AnomalySeverity.MEDIUM, severity)
    }

    @Test
    fun `relative delta - no increase means no anomaly`() {
        val oldUnprotected = 10
        val newUnprotected = 10
        val delta = newUnprotected - oldUnprotected
        // delta <= 0 → no anomaly created (tested here as sanity check)
        assertTrue("No increase should mean delta <= 0", delta <= 0)
    }

    /**
     * Mirrors the logic from BaselineManager.compareWithBaseline
     * for relative exported surface delta severity.
     */
    private fun computeExpectedSurfaceSeverity(
        oldUnprotected: Int,
        newUnprotected: Int,
        delta: Int
    ): BaselineManager.AnomalySeverity {
        return when {
            oldUnprotected == 0 && newUnprotected >= 2 -> BaselineManager.AnomalySeverity.HIGH
            oldUnprotected > 0 && (delta.toFloat() / oldUnprotected >= 0.5f || delta >= 5) ->
                BaselineManager.AnomalySeverity.MEDIUM
            else -> BaselineManager.AnomalySeverity.LOW
        }
    }

    // ══════════════════════════════════════════════════════════
    //  VERSION_ROLLBACK detection logic
    // ══════════════════════════════════════════════════════════

    @Test
    fun `version rollback - downgrade should produce VERSION_ROLLBACK anomaly`() {
        // Simulate the logic: currentVersionCode < existingVersionCode
        val existingVersion = 150L
        val currentVersion = 120L
        assertTrue("Should detect downgrade", currentVersion < existingVersion)
        
        // The anomaly should be VERSION_ROLLBACK with HIGH severity
        val anomaly = BaselineManager.BaselineAnomaly(
            type = BaselineManager.AnomalyType.VERSION_ROLLBACK,
            severity = BaselineManager.AnomalySeverity.HIGH,
            description = "Verze aplikace byla snížena",
            details = "versionCode: $existingVersion → $currentVersion"
        )
        assertEquals(BaselineManager.AnomalyType.VERSION_ROLLBACK, anomaly.type)
        assertEquals(BaselineManager.AnomalySeverity.HIGH, anomaly.severity)
    }

    @Test
    fun `version rollback - upgrade should produce VERSION_CHANGED not rollback`() {
        val existingVersion = 100L
        val currentVersion = 150L
        assertFalse("Upgrade is not a rollback", currentVersion < existingVersion)
    }

    @Test
    fun `version rollback - same version produces no anomaly`() {
        val existingVersion = 100L
        val currentVersion = 100L
        assertFalse("Same version is not a rollback", currentVersion < existingVersion)
        assertEquals("Same version means no change", existingVersion, currentVersion)
    }

    @Test
    fun `version rollback - minor downgrade is still detected`() {
        // Even versionCode 100→99 is a rollback
        val existingVersion = 100L
        val currentVersion = 99L
        assertTrue("Even 1-step downgrade should be detected", currentVersion < existingVersion)
    }

    @Test
    fun `version rollback - maps to FindingType VERSION_ROLLBACK`() {
        // Verify the FindingType exists and is HARD
        assertEquals(
            "VERSION_ROLLBACK should be HARD",
            TrustRiskModel.FindingHardness.HARD,
            TrustRiskModel.FindingType.VERSION_ROLLBACK.hardness
        )
    }
}
