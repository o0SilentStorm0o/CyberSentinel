package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AppFeatureVector data model and query helpers.
 */
class AppFeatureVectorTest {

    // ────────────────────────────────────────────────────────
    //  Helpers
    // ────────────────────────────────────────────────────────

    private fun buildVector(
        trustScore: Int = 50,
        trustLevel: TrustEvidenceEngine.TrustLevel = TrustEvidenceEngine.TrustLevel.MODERATE,
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
        effectiveRisk: TrustRiskModel.EffectiveRisk = TrustRiskModel.EffectiveRisk.SAFE,
        accessibilityEnabled: Boolean = false,
        notificationListenerEnabled: Boolean = false,
        unexpectedClusters: List<TrustRiskModel.CapabilityCluster> = emptyList(),
        anomalies: List<BaselineManager.AnomalyType> = emptyList(),
        baselineStatus: BaselineManager.BaselineStatus = BaselineManager.BaselineStatus.UNCHANGED
    ) = AppFeatureVector(
        packageName = "com.example.app",
        identity = AppFeatureVector.IdentityFeatures(
            trustScore = trustScore,
            trustLevel = trustLevel,
            certSha256 = "ABCD",
            certMatchType = TrustEvidenceEngine.CertMatchType.UNKNOWN,
            matchedDeveloper = null,
            installerType = installerType,
            installerPackage = null,
            isSystemApp = false,
            isPlatformSigned = false,
            hasSigningLineage = false,
            isNewApp = false
        ),
        change = AppFeatureVector.ChangeFeatures(
            baselineStatus = baselineStatus,
            isFirstScan = false,
            anomalies = anomalies
        ),
        capability = AppFeatureVector.CapabilityFeatures(
            activeHighRiskClusters = emptyList(),
            unexpectedClusters = unexpectedClusters,
            dangerousPermissionCount = 0,
            highRiskPermissions = emptyList(),
            privacyCapabilities = emptyList(),
            matchedCombos = emptyList(),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        ),
        surface = AppFeatureVector.SurfaceFeatures(
            exportedActivityCount = 0,
            exportedServiceCount = 0,
            exportedReceiverCount = 0,
            exportedProviderCount = 0,
            unprotectedExportedCount = 0,
            hasSuspiciousNativeLibs = false,
            nativeLibCount = 0,
            targetSdk = 34,
            minSdk = 26,
            apkSizeBytes = 1000
        ),
        specialAccess = SpecialAccessInspector.SpecialAccessSnapshot(
            packageName = "com.example.app",
            accessibilityEnabled = accessibilityEnabled,
            notificationListenerEnabled = notificationListenerEnabled
        ),
        verdict = AppFeatureVector.VerdictSummary(
            effectiveRisk = effectiveRisk,
            riskScore = 0,
            hardFindingCount = 0,
            softFindingCount = 0,
            topReasons = emptyList()
        )
    )

    // ══════════════════════════════════════════════════════════
    //  Query helper tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `hasActiveSpecialAccess - false when nothing enabled`() {
        val vector = buildVector()
        assertFalse(vector.hasActiveSpecialAccess)
    }

    @Test
    fun `hasActiveSpecialAccess - true when accessibility enabled`() {
        val vector = buildVector(accessibilityEnabled = true)
        assertTrue(vector.hasActiveSpecialAccess)
    }

    @Test
    fun `isHighPriorityTarget - low trust plus special access`() {
        val vector = buildVector(
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            accessibilityEnabled = true
        )
        assertTrue(vector.isHighPriorityTarget)
    }

    @Test
    fun `isHighPriorityTarget - false for high trust`() {
        val vector = buildVector(
            trustScore = 85,
            trustLevel = TrustEvidenceEngine.TrustLevel.HIGH,
            accessibilityEnabled = true
        )
        assertFalse(vector.isHighPriorityTarget)
    }

    @Test
    fun `isHighPriorityTarget - false without special access`() {
        val vector = buildVector(
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW
        )
        assertFalse(vector.isHighPriorityTarget)
    }

    @Test
    fun `hasRecentChanges - true with anomalies`() {
        val vector = buildVector(
            anomalies = listOf(BaselineManager.AnomalyType.CERT_CHANGED)
        )
        assertTrue(vector.hasRecentChanges)
    }

    @Test
    fun `hasRecentChanges - true for new app`() {
        val vector = buildVector(
            baselineStatus = BaselineManager.BaselineStatus.NEW
        )
        assertTrue(vector.hasRecentChanges)
    }

    @Test
    fun `hasRecentChanges - false when unchanged`() {
        val vector = buildVector()
        assertFalse(vector.hasRecentChanges)
    }

    @Test
    fun `hasSuspiciousProfile - unexpected clusters plus sideload`() {
        val vector = buildVector(
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            unexpectedClusters = listOf(TrustRiskModel.CapabilityCluster.SMS)
        )
        assertTrue(vector.hasSuspiciousProfile)
    }

    @Test
    fun `hasSuspiciousProfile - unexpected clusters plus special access`() {
        val vector = buildVector(
            unexpectedClusters = listOf(TrustRiskModel.CapabilityCluster.ACCESSIBILITY),
            accessibilityEnabled = true
        )
        assertTrue(vector.hasSuspiciousProfile)
    }

    @Test
    fun `hasSuspiciousProfile - false with no unexpected clusters`() {
        val vector = buildVector(
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED
        )
        assertFalse(vector.hasSuspiciousProfile)
    }

    @Test
    fun `shouldMonitor - true for CRITICAL verdict`() {
        val vector = buildVector(
            effectiveRisk = TrustRiskModel.EffectiveRisk.CRITICAL
        )
        assertTrue(vector.shouldMonitor)
    }

    @Test
    fun `shouldMonitor - true for NEEDS_ATTENTION verdict`() {
        val vector = buildVector(
            effectiveRisk = TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION
        )
        assertTrue(vector.shouldMonitor)
    }

    @Test
    fun `shouldMonitor - true for high priority target`() {
        val vector = buildVector(
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            accessibilityEnabled = true,
            effectiveRisk = TrustRiskModel.EffectiveRisk.INFO
        )
        assertTrue(vector.shouldMonitor)
    }

    @Test
    fun `shouldMonitor - false for safe trusted app`() {
        val vector = buildVector(
            trustScore = 85,
            trustLevel = TrustEvidenceEngine.TrustLevel.HIGH,
            effectiveRisk = TrustRiskModel.EffectiveRisk.SAFE
        )
        assertFalse(vector.shouldMonitor)
    }
}
