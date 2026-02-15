package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Comprehensive unit tests for InstallTimelineAnalyzer — temporal correlation engine.
 *
 * Tests verify:
 *  1. Fresh install detection and phase classification
 *  2. Immediate window signals (network, SMS)
 *  3. Short-term window signals (accessibility, overlay)
 *  4. Medium-term window signals (permission escalation)
 *  5. Amplifiers (low trust, sideload)
 *  6. Non-time-bound signals (boot persistence, dynamic code loading, install packages)
 *  7. Score thresholds (dropper candidate, high confidence)
 *  8. Established apps return score 0
 *  9. Batch analysis
 * 10. Edge cases (null timestamps, empty events)
 */
class InstallTimelineAnalyzerTest {

    private lateinit var analyzer: InstallTimelineAnalyzer

    // ── Time constants for readability ──
    private val minute = 60_000L
    private val hour = 3_600_000L
    private val day = 86_400_000L

    // ── Base timestamp: T0 = install time ──
    private val T0 = 1_700_000_000_000L

    @Before
    fun setUp() {
        analyzer = InstallTimelineAnalyzer()
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeApp(
        packageName: String = "com.test.dropper",
        installTime: Long = T0,
        trustScore: Int = 50,
        trustLevel: TrustEvidenceEngine.TrustLevel = TrustEvidenceEngine.TrustLevel.MODERATE,
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
        isNewApp: Boolean = true,
        activeHighRiskClusters: List<TrustRiskModel.CapabilityCluster> = emptyList(),
        accessibilityEnabled: Boolean = false,
        overlayEnabled: Boolean = false,
        exportedReceiverCount: Int = 0
    ): AppFeatureVector {
        return AppFeatureVector(
            packageName = packageName,
            timestamp = installTime,
            identity = AppFeatureVector.IdentityFeatures(
                trustScore = trustScore,
                trustLevel = trustLevel,
                certSha256 = "ABCD1234",
                certMatchType = TrustEvidenceEngine.CertMatchType.UNKNOWN,
                matchedDeveloper = null,
                installerType = installerType,
                installerPackage = null,
                isSystemApp = false,
                isPlatformSigned = false,
                hasSigningLineage = false,
                isNewApp = isNewApp
            ),
            change = AppFeatureVector.ChangeFeatures(
                baselineStatus = BaselineManager.BaselineStatus.NEW,
                isFirstScan = true,
                anomalies = emptyList(),
                lastUpdateAt = installTime
            ),
            capability = AppFeatureVector.CapabilityFeatures(
                activeHighRiskClusters = activeHighRiskClusters,
                unexpectedClusters = emptyList(),
                dangerousPermissionCount = activeHighRiskClusters.size,
                highRiskPermissions = emptyList(),
                privacyCapabilities = emptyList(),
                matchedCombos = emptyList(),
                appCategory = AppCategoryDetector.AppCategory.OTHER
            ),
            surface = AppFeatureVector.SurfaceFeatures(
                exportedActivityCount = 1,
                exportedServiceCount = 0,
                exportedReceiverCount = exportedReceiverCount,
                exportedProviderCount = 0,
                unprotectedExportedCount = 0,
                hasSuspiciousNativeLibs = false,
                nativeLibCount = 0,
                targetSdk = 34,
                minSdk = 26,
                apkSizeBytes = 1_000_000
            ),
            specialAccess = SpecialAccessInspector.SpecialAccessSnapshot(
                packageName = packageName,
                accessibilityEnabled = accessibilityEnabled,
                overlayEnabled = overlayEnabled
            ),
            verdict = AppFeatureVector.VerdictSummary(
                effectiveRisk = TrustRiskModel.EffectiveRisk.INFO,
                riskScore = 30,
                hardFindingCount = 0,
                softFindingCount = 0,
                topReasons = emptyList()
            )
        )
    }

    private fun makeSignal(
        type: SignalType,
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.dropper"
    ) = SecuritySignal(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Signal: ${type.name}"
    )

    private fun makeEvent(
        type: EventType = EventType.BEHAVIORAL_ANOMALY,
        signals: List<SecuritySignal> = emptyList(),
        pkg: String = "com.test.dropper",
        startTime: Long = T0 + 5 * minute
    ) = SecurityEvent(
        startTime = startTime,
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = SignalSeverity.HIGH,
        packageName = pkg,
        summary = "Event: ${type.name}",
        signals = signals
    )

    // ══════════════════════════════════════════════════════════
    //  1. Established app (not fresh) — score 0
    // ══════════════════════════════════════════════════════════

    @Test
    fun `established app returns zero score`() {
        val app = makeApp(installTime = T0 - 10 * day)
        val result = analyzer.analyze(app, emptyList(), now = T0)

        assertEquals(0.0, result.score, 0.001)
        assertFalse(result.isFreshInstall)
        assertEquals(InstallTimelineAnalyzer.TimelinePhase.ESTABLISHED, result.phase)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun `app installed 3 days ago is not fresh`() {
        val app = makeApp(installTime = T0 - 3 * day)
        val result = analyzer.analyze(app, emptyList(), now = T0)

        assertFalse(result.isFreshInstall)
        assertEquals(0.0, result.score, 0.001)
    }

    // ══════════════════════════════════════════════════════════
    //  2. Fresh install — base signal
    // ══════════════════════════════════════════════════════════

    @Test
    fun `fresh install produces base score`() {
        val app = makeApp(installTime = T0)
        val result = analyzer.analyze(app, emptyList(), now = T0 + 30 * minute)

        assertTrue(result.isFreshInstall)
        assertTrue(result.score > 0.0)
        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.FRESH_INSTALL
        })
    }

    @Test
    fun `phase is IMMEDIATE within 10 minutes`() {
        val app = makeApp(installTime = T0)
        val result = analyzer.analyze(app, emptyList(), now = T0 + 5 * minute)

        assertEquals(InstallTimelineAnalyzer.TimelinePhase.IMMEDIATE, result.phase)
    }

    @Test
    fun `phase is SHORT_TERM between 10min and 6h`() {
        val app = makeApp(installTime = T0)
        val result = analyzer.analyze(app, emptyList(), now = T0 + 2 * hour)

        assertEquals(InstallTimelineAnalyzer.TimelinePhase.SHORT_TERM, result.phase)
    }

    @Test
    fun `phase is MEDIUM_TERM between 6h and 48h`() {
        val app = makeApp(installTime = T0)
        val result = analyzer.analyze(app, emptyList(), now = T0 + 24 * hour)

        assertEquals(InstallTimelineAnalyzer.TimelinePhase.MEDIUM_TERM, result.phase)
    }

    // ══════════════════════════════════════════════════════════
    //  3. Immediate window signals
    // ══════════════════════════════════════════════════════════

    @Test
    fun `network burst in immediate window adds signal`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.NETWORK_BURST_ANOMALY)),
                startTime = T0 + 3 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 5 * minute)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.IMMEDIATE_NETWORK_BURST
        })
        assertTrue(result.score > 0.2) // base + network
    }

    @Test
    fun `NETWORK_AFTER_INSTALL signal in immediate window`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.NETWORK_AFTER_INSTALL)),
                startTime = T0 + 2 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 5 * minute)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.IMMEDIATE_NETWORK_BURST
        })
    }

    @Test
    fun `SMS capability in immediate window adds signal`() {
        val app = makeApp(
            installTime = T0,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.SMS)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 5 * minute)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.IMMEDIATE_SMS_ACCESS
        })
    }

    // ══════════════════════════════════════════════════════════
    //  4. Short-term window signals
    // ══════════════════════════════════════════════════════════

    @Test
    fun `accessibility in short window adds signal`() {
        val app = makeApp(
            installTime = T0,
            accessibilityEnabled = true,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.ACCESSIBILITY)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 2 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.SHORT_TERM_ACCESSIBILITY
        })
    }

    @Test
    fun `overlay in short window adds signal`() {
        val app = makeApp(
            installTime = T0,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.OVERLAY)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 3 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.SHORT_TERM_OVERLAY
        })
    }

    @Test
    fun `SPECIAL_ACCESS_ENABLED event triggers accessibility signal`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.SPECIAL_ACCESS_ENABLED)),
                startTime = T0 + hour
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 2 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.SHORT_TERM_ACCESSIBILITY
        })
    }

    @Test
    fun `UNKNOWN_ACCESSIBILITY_SERVICE event triggers accessibility signal`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.UNKNOWN_ACCESSIBILITY_SERVICE)),
                startTime = T0 + 2 * hour
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 3 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.SHORT_TERM_ACCESSIBILITY
        })
    }

    // ══════════════════════════════════════════════════════════
    //  5. Medium-term window signals
    // ══════════════════════════════════════════════════════════

    @Test
    fun `permission escalation in medium window adds signal`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.HIGH_RISK_PERM_ADDED)),
                startTime = T0 + 12 * hour
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 24 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.MEDIUM_TERM_ESCALATION
        })
    }

    @Test
    fun `POST_INSTALL_PERMISSION_ESCALATION signal adds escalation`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.POST_INSTALL_PERMISSION_ESCALATION)),
                startTime = T0 + 8 * hour
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 12 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.MEDIUM_TERM_ESCALATION
        })
    }

    // ══════════════════════════════════════════════════════════
    //  6. Non-time-bound signals
    // ══════════════════════════════════════════════════════════

    @Test
    fun `boot persistence signal detected`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.BOOT_PERSISTENCE)),
                startTime = T0 + hour
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 2 * hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.BOOT_PERSISTENCE
        })
    }

    @Test
    fun `exported receiver on new app detected as boot persistence`() {
        val app = makeApp(
            installTime = T0,
            isNewApp = true,
            exportedReceiverCount = 2
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.BOOT_PERSISTENCE
        })
    }

    @Test
    fun `dynamic code loading signal detected`() {
        val app = makeApp(installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.DYNAMIC_CODE_LOADING)),
                startTime = T0 + 30 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.DYNAMIC_CODE_LOADING
        })
    }

    @Test
    fun `fresh install with install packages permission`() {
        val app = makeApp(
            installTime = T0,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.FRESH_INSTALL_WITH_INSTALLER_PERM
        })
    }

    // ══════════════════════════════════════════════════════════
    //  7. Amplifiers
    // ══════════════════════════════════════════════════════════

    @Test
    fun `low trust amplifies score`() {
        val appNormal = makeApp(installTime = T0, trustScore = 50, trustLevel = TrustEvidenceEngine.TrustLevel.MODERATE)
        val appLow = makeApp(installTime = T0, trustScore = 20, trustLevel = TrustEvidenceEngine.TrustLevel.LOW)

        val resultNormal = analyzer.analyze(appNormal, emptyList(), now = T0 + hour)
        val resultLow = analyzer.analyze(appLow, emptyList(), now = T0 + hour)

        assertTrue("Low trust should increase score", resultLow.score > resultNormal.score)
        assertTrue(resultLow.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.LOW_TRUST_AMPLIFIER
        })
    }

    @Test
    fun `anomalous trust also amplifies score`() {
        val app = makeApp(installTime = T0, trustScore = 5, trustLevel = TrustEvidenceEngine.TrustLevel.ANOMALOUS)
        val result = analyzer.analyze(app, emptyList(), now = T0 + hour)

        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.LOW_TRUST_AMPLIFIER
        })
    }

    @Test
    fun `sideload amplifies score`() {
        val appStore = makeApp(installTime = T0, installerType = TrustEvidenceEngine.InstallerType.PLAY_STORE)
        val appSideload = makeApp(installTime = T0, installerType = TrustEvidenceEngine.InstallerType.SIDELOADED)

        val resultStore = analyzer.analyze(appStore, emptyList(), now = T0 + hour)
        val resultSideload = analyzer.analyze(appSideload, emptyList(), now = T0 + hour)

        assertTrue("Sideload should increase score", resultSideload.score > resultStore.score)
        assertTrue(resultSideload.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.SIDELOAD_AMPLIFIER
        })
    }

    // ══════════════════════════════════════════════════════════
    //  8. Full dropper scenario — high confidence
    // ══════════════════════════════════════════════════════════

    @Test
    fun `full dropper scenario - fresh install + sideload + low trust + accessibility + overlay + network = high score`() {
        val app = makeApp(
            installTime = T0,
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isNewApp = true,
            activeHighRiskClusters = listOf(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                TrustRiskModel.CapabilityCluster.OVERLAY,
                TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES
            ),
            accessibilityEnabled = true
        )
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.NETWORK_AFTER_INSTALL)),
                startTime = T0 + 2 * minute
            ),
            makeEvent(
                signals = listOf(makeSignal(SignalType.BOOT_PERSISTENCE)),
                startTime = T0 + 30 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + hour)

        assertTrue("Full dropper should be high confidence", result.isHighConfidenceDropper)
        assertTrue("Score should be >= 0.55", result.score >= 0.55)
        assertTrue(result.isDropperCandidate)
        assertTrue(result.isFreshInstall)
    }

    @Test
    fun `moderate scenario - fresh install + overlay only = candidate but not high confidence`() {
        val app = makeApp(
            installTime = T0,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.OVERLAY)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 2 * hour)

        // base(0.10) + overlay(0.20) = 0.30
        assertTrue("Should be dropper candidate", result.isDropperCandidate)
        assertFalse("Should NOT be high confidence", result.isHighConfidenceDropper)
    }

    @Test
    fun `minimal scenario - fresh install only = not candidate`() {
        val app = makeApp(installTime = T0)
        val result = analyzer.analyze(app, emptyList(), now = T0 + hour)

        // Only base signal (0.10)
        assertFalse("Fresh install alone should not be candidate", result.isDropperCandidate)
    }

    // ══════════════════════════════════════════════════════════
    //  9. Score is clamped to [0, 1]
    // ══════════════════════════════════════════════════════════

    @Test
    fun `score never exceeds 1_0`() {
        val app = makeApp(
            installTime = T0,
            trustScore = 5,
            trustLevel = TrustEvidenceEngine.TrustLevel.ANOMALOUS,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isNewApp = true,
            activeHighRiskClusters = listOf(
                TrustRiskModel.CapabilityCluster.SMS,
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                TrustRiskModel.CapabilityCluster.OVERLAY,
                TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES
            ),
            accessibilityEnabled = true,
            exportedReceiverCount = 3
        )
        val events = listOf(
            makeEvent(
                signals = listOf(
                    makeSignal(SignalType.NETWORK_AFTER_INSTALL),
                    makeSignal(SignalType.DYNAMIC_CODE_LOADING),
                    makeSignal(SignalType.BOOT_PERSISTENCE),
                    makeSignal(SignalType.POST_INSTALL_PERMISSION_ESCALATION)
                ),
                startTime = T0 + 3 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 5 * minute)

        assertTrue("Score should be clamped to 1.0", result.score <= 1.0)
        assertTrue("Score should be high", result.score >= 0.55)
    }

    // ══════════════════════════════════════════════════════════
    //  10. Batch analysis
    // ══════════════════════════════════════════════════════════

    @Test
    fun `analyzeAll filters out zero-score apps and sorts descending`() {
        val freshDropper = makeApp(
            packageName = "com.evil.dropper",
            installTime = T0,
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            activeHighRiskClusters = listOf(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                TrustRiskModel.CapabilityCluster.OVERLAY
            ),
            accessibilityEnabled = true
        )
        val freshBenign = makeApp(
            packageName = "com.benign.app",
            installTime = T0,
            trustScore = 70,
            trustLevel = TrustEvidenceEngine.TrustLevel.HIGH
        )
        val established = makeApp(
            packageName = "com.old.app",
            installTime = T0 - 10 * day,
            isNewApp = false
        )

        val results = analyzer.analyzeAll(
            apps = listOf(freshDropper, freshBenign, established),
            recentEvents = emptyList(),
            now = T0 + 2 * hour
        )

        // Established app has score 0, should be filtered out
        assertTrue("Established app should be excluded", results.none { it.packageName == "com.old.app" })

        // Both fresh apps should be included (both have base score > 0)
        assertTrue("Fresh apps should be included", results.isNotEmpty())

        // Sorted descending
        if (results.size >= 2) {
            assertTrue("Should be sorted descending", results[0].score >= results[1].score)
        }

        // Dropper should have higher score
        val dropperResult = results.find { it.packageName == "com.evil.dropper" }
        val benignResult = results.find { it.packageName == "com.benign.app" }
        if (dropperResult != null && benignResult != null) {
            assertTrue("Dropper should score higher", dropperResult.score > benignResult.score)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  11. Events for different package are ignored
    // ══════════════════════════════════════════════════════════

    @Test
    fun `events for other package are ignored`() {
        val app = makeApp(packageName = "com.test.dropper", installTime = T0)
        val events = listOf(
            makeEvent(
                signals = listOf(makeSignal(SignalType.NETWORK_AFTER_INSTALL, pkg = "com.other.app")),
                pkg = "com.other.app",
                startTime = T0 + 2 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 5 * minute)

        // Should NOT have network burst signal (event is for different package)
        assertFalse(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.IMMEDIATE_NETWORK_BURST
        })
    }

    // ══════════════════════════════════════════════════════════
    //  12. Edge cases
    // ══════════════════════════════════════════════════════════

    @Test
    fun `empty events list produces only static signals`() {
        val app = makeApp(
            installTime = T0,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.OVERLAY)
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 2 * hour)

        assertTrue(result.signals.isNotEmpty())
        // Should have FRESH_INSTALL + SHORT_TERM_OVERLAY
        assertTrue(result.signals.any { it.type == InstallTimelineAnalyzer.TimelineSignalType.FRESH_INSTALL })
        assertTrue(result.signals.any { it.type == InstallTimelineAnalyzer.TimelineSignalType.SHORT_TERM_OVERLAY })
    }

    @Test
    fun `formatAge formats correctly`() {
        assertEquals("30 s", analyzer.formatAge(30_000))
        assertEquals("5 min", analyzer.formatAge(5 * minute))
        assertEquals("2 h", analyzer.formatAge(2 * hour))
        assertEquals("3 d", analyzer.formatAge(3 * day))
    }

    // ══════════════════════════════════════════════════════════
    //  13. Banking overlay scenario
    // ══════════════════════════════════════════════════════════

    @Test
    fun `banking overlay pattern - fresh install + overlay + accessibility + sideload`() {
        val app = makeApp(
            installTime = T0,
            trustScore = 20,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isNewApp = true,
            activeHighRiskClusters = listOf(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                TrustRiskModel.CapabilityCluster.OVERLAY
            ),
            accessibilityEnabled = true
        )
        val result = analyzer.analyze(app, emptyList(), now = T0 + 3 * hour)

        // base(0.10) + accessibility(0.25) + overlay(0.20) + low_trust(0.15) + sideload(0.10) = 0.80
        assertTrue("Banking overlay should be high confidence dropper", result.isHighConfidenceDropper)
        assertTrue("Score should be high", result.score >= 0.55)
    }

    // ══════════════════════════════════════════════════════════
    //  14. Loader scenario
    // ══════════════════════════════════════════════════════════

    @Test
    fun `loader pattern - fresh install + network + dynamic code loading + low trust`() {
        val app = makeApp(
            installTime = T0,
            trustScore = 25,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            isNewApp = true
        )
        val events = listOf(
            makeEvent(
                signals = listOf(
                    makeSignal(SignalType.NETWORK_AFTER_INSTALL),
                    makeSignal(SignalType.DYNAMIC_CODE_LOADING)
                ),
                startTime = T0 + 3 * minute
            )
        )
        val result = analyzer.analyze(app, events, now = T0 + 5 * minute)

        // base(0.10) + network(0.15) + dynamic(0.15) + low_trust(0.15) = 0.55
        assertTrue("Loader pattern should be dropper candidate", result.isDropperCandidate)
        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.DYNAMIC_CODE_LOADING
        })
        assertTrue(result.signals.any {
            it.type == InstallTimelineAnalyzer.TimelineSignalType.IMMEDIATE_NETWORK_BURST
        })
    }
}
