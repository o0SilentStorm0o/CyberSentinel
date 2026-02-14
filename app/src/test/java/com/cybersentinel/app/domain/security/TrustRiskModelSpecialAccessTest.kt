package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for TrustRiskModel SpecialAccess integration.
 *
 * Tests that cluster activation is properly gated by real enabled state
 * when specialAccessSnapshot is provided.
 */
class TrustRiskModelSpecialAccessTest {

    private lateinit var model: TrustRiskModel

    // ────────────────────────────────────────────────────────
    //  Helpers
    // ────────────────────────────────────────────────────────

    private fun lowTrustSideloaded() = TrustEvidenceEngine.TrustEvidence(
        packageName = "com.example.app",
        certSha256 = "ABCD1234",
        certMatch = TrustEvidenceEngine.CertMatchResult(
            matchType = TrustEvidenceEngine.CertMatchType.UNKNOWN,
            matchedDeveloper = null,
            knownCertDigests = emptySet(),
            currentCertDigest = "ABCD1234"
        ),
        installerInfo = TrustEvidenceEngine.InstallerInfo(
            installerPackage = null,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isExpectedInstaller = false
        ),
        systemAppInfo = TrustEvidenceEngine.SystemAppInfo(
            isSystemApp = false, isPrivilegedApp = false,
            isUpdatedSystemApp = false,
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isPlatformSigned = false
        ),
        signingLineage = TrustEvidenceEngine.SigningLineageInfo(false, 0, false),
        deviceIntegrity = TrustEvidenceEngine.DeviceIntegrityInfo(false, TrustEvidenceEngine.VerifiedBootState.GREEN),
        trustScore = 15,
        trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
        reasons = emptyList()
    )

    private fun highTrust() = TrustEvidenceEngine.TrustEvidence(
        packageName = "com.example.app",
        certSha256 = "ABCD1234",
        certMatch = TrustEvidenceEngine.CertMatchResult(
            matchType = TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH,
            matchedDeveloper = "TestDev",
            knownCertDigests = emptySet(),
            currentCertDigest = "ABCD1234"
        ),
        installerInfo = TrustEvidenceEngine.InstallerInfo(
            installerPackage = "com.android.vending",
            installerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
            isExpectedInstaller = true
        ),
        systemAppInfo = TrustEvidenceEngine.SystemAppInfo(
            isSystemApp = false, isPrivilegedApp = false,
            isUpdatedSystemApp = false,
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isPlatformSigned = false
        ),
        signingLineage = TrustEvidenceEngine.SigningLineageInfo(false, 0, false),
        deviceIntegrity = TrustEvidenceEngine.DeviceIntegrityInfo(false, TrustEvidenceEngine.VerifiedBootState.GREEN),
        trustScore = 85,
        trustLevel = TrustEvidenceEngine.TrustLevel.HIGH,
        reasons = emptyList()
    )

    private fun snapshot(
        accessibilityEnabled: Boolean = false,
        notificationListenerEnabled: Boolean = false,
        deviceAdminEnabled: Boolean = false,
        overlayEnabled: Boolean = false
    ) = SpecialAccessInspector.SpecialAccessSnapshot(
        packageName = "com.example.app",
        accessibilityEnabled = accessibilityEnabled,
        notificationListenerEnabled = notificationListenerEnabled,
        deviceAdminEnabled = deviceAdminEnabled,
        overlayEnabled = overlayEnabled
    )

    @Before
    fun setup() {
        model = TrustRiskModel()
    }

    // ══════════════════════════════════════════════════════════
    //  Cluster gating tests — special access snapshot
    // ══════════════════════════════════════════════════════════

    @Test
    fun `accessibility cluster NOT active when service is not enabled`() {
        // App declares BIND_ACCESSIBILITY_SERVICE but user never enabled it
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            specialAccessSnapshot = snapshot(accessibilityEnabled = false)
        )
        // Without real accessibility enabled, no combo → should not be CRITICAL
        assertNotEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        // Accessibility cluster should NOT be in active clusters
        assertFalse(verdict.activeClusters.contains(TrustRiskModel.CapabilityCluster.ACCESSIBILITY))
    }

    @Test
    fun `accessibility cluster ACTIVE when service is enabled`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            specialAccessSnapshot = snapshot(accessibilityEnabled = true, overlayEnabled = true)
        )
        // With real accessibility + overlay enabled + sideloaded → combo should fire
        assertTrue(verdict.activeClusters.contains(TrustRiskModel.CapabilityCluster.ACCESSIBILITY))
        assertTrue(verdict.activeClusters.contains(TrustRiskModel.CapabilityCluster.OVERLAY))
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `notification listener cluster gated by real enabled state`() {
        // Declared but NOT enabled → cluster NOT active
        val verdictDisabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            specialAccessSnapshot = snapshot(notificationListenerEnabled = false)
        )
        assertFalse(verdictDisabled.activeClusters.contains(TrustRiskModel.CapabilityCluster.NOTIFICATION_LISTENER))

        // Declared AND enabled → cluster ACTIVE
        val verdictEnabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            specialAccessSnapshot = snapshot(notificationListenerEnabled = true)
        )
        assertTrue(verdictEnabled.activeClusters.contains(TrustRiskModel.CapabilityCluster.NOTIFICATION_LISTENER))
    }

    @Test
    fun `device admin cluster gated by real enabled state`() {
        val verdictDisabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_DEVICE_ADMIN"),
            specialAccessSnapshot = snapshot(deviceAdminEnabled = false)
        )
        assertFalse(verdictDisabled.activeClusters.contains(TrustRiskModel.CapabilityCluster.DEVICE_ADMIN))

        val verdictEnabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_DEVICE_ADMIN"),
            specialAccessSnapshot = snapshot(deviceAdminEnabled = true)
        )
        assertTrue(verdictEnabled.activeClusters.contains(TrustRiskModel.CapabilityCluster.DEVICE_ADMIN))
    }

    @Test
    fun `overlay cluster gated by real enabled state`() {
        val verdictDisabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.SYSTEM_ALERT_WINDOW"),
            specialAccessSnapshot = snapshot(overlayEnabled = false)
        )
        assertFalse(verdictDisabled.activeClusters.contains(TrustRiskModel.CapabilityCluster.OVERLAY))
    }

    @Test
    fun `non-special-access clusters still use manifest permissions`() {
        // SMS cluster is NOT a special-access cluster — should still be active from manifest
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            specialAccessSnapshot = snapshot() // no special access enabled
        )
        // SMS cluster should be active (it's manifest-based, not special-access-gated)
        assertTrue(verdict.activeClusters.contains(TrustRiskModel.CapabilityCluster.SMS))
    }

    @Test
    fun `legacy mode - null snapshot uses manifest-only`() {
        // When no snapshot provided, fall back to manifest-only (backward compat)
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            specialAccessSnapshot = null // legacy mode
        )
        // In legacy mode, accessibility should be active based on manifest alone
        assertTrue(verdict.activeClusters.contains(TrustRiskModel.CapabilityCluster.ACCESSIBILITY))
    }

    @Test
    fun `stalkerware combo requires REAL accessibility AND notification listener enabled`() {
        val permissions = listOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        )

        // Both declared but NOT enabled → no stalkerware combo
        val verdictNotEnabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = permissions,
            specialAccessSnapshot = snapshot(
                accessibilityEnabled = false,
                notificationListenerEnabled = false
            )
        )
        assertTrue(verdictNotEnabled.matchedCombos.isEmpty())
        assertNotEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdictNotEnabled.effectiveRisk)

        // Both declared AND enabled → stalkerware combo fires
        val verdictEnabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = permissions,
            specialAccessSnapshot = snapshot(
                accessibilityEnabled = true,
                notificationListenerEnabled = true
            )
        )
        assertTrue(verdictEnabled.matchedCombos.isNotEmpty())
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdictEnabled.effectiveRisk)
    }

    @Test
    fun `overlay attack combo requires REAL overlay enabled`() {
        val permissions = listOf(
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW"
        )

        // Overlay NOT enabled → combo should not fire
        val verdictNotEnabled = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrustSideloaded(),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = permissions,
            specialAccessSnapshot = snapshot(
                notificationListenerEnabled = true,
                overlayEnabled = false
            )
        )
        // Should not match the "notification + overlay" combo
        val overlayCombo = verdictNotEnabled.matchedCombos.any { it.contains("overlay", ignoreCase = true) }
        assertFalse(overlayCombo)
    }

    // ══════════════════════════════════════════════════════════
    //  INSTALLER_ANOMALY_VERIFIED tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `INSTALLER_ANOMALY_VERIFIED is SOFT and does not escalate to CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                TrustRiskModel.RawFinding(
                    TrustRiskModel.FindingType.INSTALLER_ANOMALY_VERIFIED,
                    AppSecurityScanner.RiskLevel.LOW,
                    "Ruční instalace ověřené aplikace",
                    ""
                )
            ),
            isSystemApp = false
        )
        // INSTALLER_ANOMALY_VERIFIED is SOFT → should not trigger CRITICAL
        assertNotEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `INSTALLER_ANOMALY (HARD) still escalates to CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                TrustRiskModel.RawFinding(
                    TrustRiskModel.FindingType.INSTALLER_ANOMALY,
                    AppSecurityScanner.RiskLevel.HIGH,
                    "Podezřelý zdroj instalace",
                    ""
                )
            ),
            isSystemApp = false
        )
        // INSTALLER_ANOMALY is HARD → should trigger CRITICAL
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }
}
