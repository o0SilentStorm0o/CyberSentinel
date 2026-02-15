package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for DefaultRootCauseResolver — hypothesis generation and ranking.
 *
 * Tests cover:
 *  1. DROPPER_PATTERN event → dropper hypothesis with trust/sideload/overlay boosting
 *  2. OVERLAY_ATTACK_PATTERN event → overlay + banking overlay hypotheses
 *  3. STAGED_PAYLOAD event → staged payload + dropper hypotheses
 *  4. LOADER_BEHAVIOR event → loader + generic hypotheses
 *  5. Cross-event correlation boost
 *  6. Action generation (uninstall, revoke, monitor)
 *  7. Severity mapping
 *  8. Batch resolution (resolveAll)
 */
class DefaultRootCauseResolverTest {

    private lateinit var resolver: DefaultRootCauseResolver

    @Before
    fun setUp() {
        resolver = DefaultRootCauseResolver()
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeApp(
        packageName: String = "com.test.app",
        trustScore: Int = 50,
        trustLevel: TrustEvidenceEngine.TrustLevel = TrustEvidenceEngine.TrustLevel.MODERATE,
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
        isNewApp: Boolean = false,
        activeHighRiskClusters: List<TrustRiskModel.CapabilityCluster> = emptyList(),
        accessibilityEnabled: Boolean = false,
        overlayEnabled: Boolean = false
    ): AppFeatureVector {
        return AppFeatureVector(
            packageName = packageName,
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
                anomalies = emptyList()
            ),
            capability = AppFeatureVector.CapabilityFeatures(
                activeHighRiskClusters = activeHighRiskClusters,
                unexpectedClusters = emptyList(),
                dangerousPermissionCount = 0,
                highRiskPermissions = emptyList(),
                privacyCapabilities = emptyList(),
                matchedCombos = emptyList(),
                appCategory = AppCategoryDetector.AppCategory.OTHER
            ),
            surface = AppFeatureVector.SurfaceFeatures(
                exportedActivityCount = 1,
                exportedServiceCount = 0,
                exportedReceiverCount = 0,
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
        pkg: String = "com.test.app"
    ) = SecuritySignal(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = SignalSeverity.HIGH,
        packageName = pkg,
        summary = "Signal: ${type.name}"
    )

    private fun makeEvent(
        type: EventType,
        signals: List<SecuritySignal> = emptyList(),
        severity: SignalSeverity = SignalSeverity.HIGH,
        pkg: String = "com.test.app"
    ) = SecurityEvent(
        source = SignalSource.APP_SCANNER,
        type = type,
        severity = severity,
        packageName = pkg,
        summary = "Event: ${type.name}",
        signals = signals
    )

    // ══════════════════════════════════════════════════════════
    //  1. DROPPER_PATTERN hypothesis
    // ══════════════════════════════════════════════════════════

    @Test
    fun `dropper pattern produces dropper hypothesis`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val incident = resolver.resolve(event)

        assertTrue(incident.hypotheses.isNotEmpty())
        val dropper = incident.hypotheses.first()
        assertTrue(dropper.name.contains("Dropper", ignoreCase = true))
        assertTrue(dropper.confidence >= 0.5)
    }

    @Test
    fun `dropper hypothesis boosted by low trust`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val appLow = makeApp(trustScore = 20, trustLevel = TrustEvidenceEngine.TrustLevel.LOW)
        val appHigh = makeApp(trustScore = 80, trustLevel = TrustEvidenceEngine.TrustLevel.HIGH)

        val incidentLow = resolver.resolve(event, appLow)
        val incidentHigh = resolver.resolve(event, appHigh)

        val confLow = incidentLow.hypotheses.first().confidence
        val confHigh = incidentHigh.hypotheses.first().confidence

        assertTrue("Low trust should boost confidence", confLow > confHigh)
    }

    @Test
    fun `dropper hypothesis boosted by sideload`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val appSideload = makeApp(installerType = TrustEvidenceEngine.InstallerType.SIDELOADED)
        val appStore = makeApp(installerType = TrustEvidenceEngine.InstallerType.PLAY_STORE)

        val confSideload = resolver.resolve(event, appSideload).hypotheses.first().confidence
        val confStore = resolver.resolve(event, appStore).hypotheses.first().confidence

        assertTrue("Sideload should boost confidence", confSideload > confStore)
    }

    @Test
    fun `dropper hypothesis boosted by new app`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val appNew = makeApp(isNewApp = true)
        val appOld = makeApp(isNewApp = false)

        val confNew = resolver.resolve(event, appNew).hypotheses.first().confidence
        val confOld = resolver.resolve(event, appOld).hypotheses.first().confidence

        assertTrue("New app should boost confidence", confNew > confOld)
    }

    @Test
    fun `dropper hypothesis boosted by overlay capability`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val appOverlay = makeApp(
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.OVERLAY)
        )
        val appNoOverlay = makeApp()

        val confOverlay = resolver.resolve(event, appOverlay).hypotheses.first().confidence
        val confNoOverlay = resolver.resolve(event, appNoOverlay).hypotheses.first().confidence

        assertTrue("Overlay should boost confidence", confOverlay > confNoOverlay)
    }

    @Test
    fun `dropper hypothesis has contradicting evidence for high trust`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val app = makeApp(trustScore = 80, trustLevel = TrustEvidenceEngine.TrustLevel.HIGH)

        val hypothesis = resolver.resolve(event, app).hypotheses.first()
        assertTrue(hypothesis.contradictingEvidence.isNotEmpty())
    }

    @Test
    fun `dropper hypothesis has MITRE technique T1544`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val hypothesis = resolver.resolve(event).hypotheses.first()
        assertTrue(hypothesis.mitreTechniques.contains("T1544"))
    }

    // ══════════════════════════════════════════════════════════
    //  2. OVERLAY_ATTACK_PATTERN → overlay + banking overlay
    // ══════════════════════════════════════════════════════════

    @Test
    fun `overlay attack produces two hypotheses`() {
        val event = makeEvent(EventType.OVERLAY_ATTACK_PATTERN)
        val incident = resolver.resolve(event)

        assertEquals("Should produce overlay + banking overlay", 2, incident.hypotheses.size)
        assertTrue(incident.hypotheses.any { it.name.contains("Overlay", ignoreCase = true) })
        assertTrue(incident.hypotheses.any { it.name.contains("Bankovní", ignoreCase = true) })
    }

    @Test
    fun `banking overlay boosted by accessibility`() {
        val event = makeEvent(EventType.OVERLAY_ATTACK_PATTERN)
        val appWithA11y = makeApp(
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.ACCESSIBILITY)
        )
        val appNoA11y = makeApp()

        val incidentA11y = resolver.resolve(event, appWithA11y)
        val incidentNoA11y = resolver.resolve(event, appNoA11y)

        val bankingA11y = incidentA11y.hypotheses.find { it.name.contains("Bankovní") }!!
        val bankingNoA11y = incidentNoA11y.hypotheses.find { it.name.contains("Bankovní") }!!

        assertTrue("Accessibility should boost banking overlay", bankingA11y.confidence > bankingNoA11y.confidence)
    }

    @Test
    fun `banking overlay boosted by fresh install`() {
        val event = makeEvent(EventType.OVERLAY_ATTACK_PATTERN)
        val appNew = makeApp(isNewApp = true)
        val appOld = makeApp(isNewApp = false)

        val bankNew = resolver.resolve(event, appNew).hypotheses.find { it.name.contains("Bankovní") }!!
        val bankOld = resolver.resolve(event, appOld).hypotheses.find { it.name.contains("Bankovní") }!!

        assertTrue("New app should boost banking overlay", bankNew.confidence > bankOld.confidence)
    }

    @Test
    fun `banking overlay has MITRE T1660 and T1417`() {
        val event = makeEvent(EventType.OVERLAY_ATTACK_PATTERN)
        val banking = resolver.resolve(event).hypotheses.find { it.name.contains("Bankovní") }!!
        assertTrue(banking.mitreTechniques.containsAll(listOf("T1660", "T1417")))
    }

    // ══════════════════════════════════════════════════════════
    //  3. STAGED_PAYLOAD → staged + dropper hypotheses
    // ══════════════════════════════════════════════════════════

    @Test
    fun `staged payload produces two hypotheses`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD)
        val incident = resolver.resolve(event)

        assertEquals(2, incident.hypotheses.size)
        assertTrue(incident.hypotheses.any { it.name.contains("Staged", ignoreCase = true) })
        assertTrue(incident.hypotheses.any { it.name.contains("Dropper", ignoreCase = true) })
    }

    @Test
    fun `staged payload boosted by new app + sideload + install packages`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD)
        val app = makeApp(
            isNewApp = true,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES)
        )

        val staged = resolver.resolve(event, app).hypotheses.find { it.name.contains("Staged") }!!
        assertTrue("Fully boosted staged should be high confidence", staged.confidence >= 0.8)
    }

    @Test
    fun `staged payload reduced by high trust`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD)
        val app = makeApp(trustScore = 85, trustLevel = TrustEvidenceEngine.TrustLevel.HIGH)

        val staged = resolver.resolve(event, app).hypotheses.find { it.name.contains("Staged") }!!
        assertTrue(staged.contradictingEvidence.isNotEmpty())
        assertTrue("High trust should reduce staged confidence", staged.confidence < 0.55)
    }

    @Test
    fun `staged payload has MITRE T1544 and T1407`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD)
        val staged = resolver.resolve(event).hypotheses.find { it.name.contains("Staged") }!!
        assertTrue(staged.mitreTechniques.containsAll(listOf("T1544", "T1407")))
    }

    // ══════════════════════════════════════════════════════════
    //  4. LOADER_BEHAVIOR → loader + generic hypotheses
    // ══════════════════════════════════════════════════════════

    @Test
    fun `loader behavior produces two hypotheses`() {
        val event = makeEvent(EventType.LOADER_BEHAVIOR)
        val incident = resolver.resolve(event)

        assertEquals(2, incident.hypotheses.size)
        assertTrue(incident.hypotheses.any { it.name.contains("Loader", ignoreCase = true) })
    }

    @Test
    fun `loader boosted by network signals`() {
        val eventWithNetwork = makeEvent(
            EventType.LOADER_BEHAVIOR,
            signals = listOf(
                makeSignal(SignalType.NETWORK_AFTER_INSTALL),
                makeSignal(SignalType.DYNAMIC_CODE_LOADING)
            )
        )
        val eventWithout = makeEvent(EventType.LOADER_BEHAVIOR)

        val app = makeApp(isNewApp = true, trustScore = 20, trustLevel = TrustEvidenceEngine.TrustLevel.LOW)

        val confWithNetwork = resolver.resolve(eventWithNetwork, app).hypotheses
            .find { it.name.contains("Loader") }!!.confidence
        val confWithout = resolver.resolve(eventWithout, app).hypotheses
            .find { it.name.contains("Loader") }!!.confidence

        assertTrue("Network signals should boost loader", confWithNetwork > confWithout)
    }

    @Test
    fun `loader has MITRE T1407`() {
        val event = makeEvent(EventType.LOADER_BEHAVIOR)
        val loader = resolver.resolve(event).hypotheses.find { it.name.contains("Loader") }!!
        assertTrue(loader.mitreTechniques.contains("T1407"))
    }

    // ══════════════════════════════════════════════════════════
    //  5. Cross-event correlation boost
    // ══════════════════════════════════════════════════════════

    @Test
    fun `multiple recent events boost confidence`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, pkg = "com.test.app")
        val recentEvents = listOf(
            makeEvent(EventType.BEHAVIORAL_ANOMALY, pkg = "com.test.app"),
            makeEvent(EventType.CAPABILITY_ESCALATION, pkg = "com.test.app")
        )

        val incidentNoRecent = resolver.resolve(event, recentEvents = emptyList())
        val incidentWithRecent = resolver.resolve(event, recentEvents = recentEvents)

        val confNoRecent = incidentNoRecent.hypotheses.first().confidence
        val confWithRecent = incidentWithRecent.hypotheses.first().confidence

        assertTrue("Recent events should boost confidence", confWithRecent > confNoRecent)
    }

    @Test
    fun `cross-event adds evidence text`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, pkg = "com.test.app")
        val recentEvents = listOf(
            makeEvent(EventType.BEHAVIORAL_ANOMALY, pkg = "com.test.app"),
            makeEvent(EventType.CAPABILITY_ESCALATION, pkg = "com.test.app")
        )

        val incident = resolver.resolve(event, recentEvents = recentEvents)
        assertTrue(
            incident.hypotheses.first().supportingEvidence.any {
                it.contains("Více bezpečnostních událostí")
            }
        )
    }

    // ══════════════════════════════════════════════════════════
    //  6. Action generation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `high confidence dropper generates uninstall action`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, pkg = "com.evil.dropper")
        val app = makeApp(
            packageName = "com.evil.dropper",
            trustScore = 15,
            trustLevel = TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isNewApp = true,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.OVERLAY)
        )

        val incident = resolver.resolve(event, app)

        assertTrue(
            incident.recommendedActions.any { it.type == ActionCategory.UNINSTALL }
        )
    }

    @Test
    fun `app with special access generates revoke action`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, pkg = "com.evil.dropper")
        val app = makeApp(
            packageName = "com.evil.dropper",
            accessibilityEnabled = true
        )

        val incident = resolver.resolve(event, app)

        assertTrue(
            incident.recommendedActions.any { it.type == ActionCategory.REVOKE_SPECIAL_ACCESS }
        )
    }

    @Test
    fun `monitor action always included`() {
        val event = makeEvent(EventType.DROPPER_PATTERN)
        val incident = resolver.resolve(event)

        assertTrue(
            incident.recommendedActions.any { it.type == ActionCategory.MONITOR }
        )
    }

    // ══════════════════════════════════════════════════════════
    //  7. Severity mapping
    // ══════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL event maps to CRITICAL incident`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, severity = SignalSeverity.CRITICAL)
        val incident = resolver.resolve(event)
        assertEquals(IncidentSeverity.CRITICAL, incident.severity)
    }

    @Test
    fun `HIGH event maps to HIGH incident`() {
        val event = makeEvent(EventType.DROPPER_PATTERN, severity = SignalSeverity.HIGH)
        val incident = resolver.resolve(event)
        assertEquals(IncidentSeverity.HIGH, incident.severity)
    }

    @Test
    fun `MEDIUM event maps to MEDIUM incident`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD, severity = SignalSeverity.MEDIUM)
        val incident = resolver.resolve(event)
        assertEquals(IncidentSeverity.MEDIUM, incident.severity)
    }

    // ══════════════════════════════════════════════════════════
    //  8. Batch resolution
    // ══════════════════════════════════════════════════════════

    @Test
    fun `resolveAll produces one incident per event`() {
        val events = listOf(
            makeEvent(EventType.DROPPER_PATTERN, pkg = "com.evil.one"),
            makeEvent(EventType.OVERLAY_ATTACK_PATTERN, pkg = "com.evil.two"),
            makeEvent(EventType.LOADER_BEHAVIOR, pkg = "com.evil.three")
        )

        val incidents = resolver.resolveAll(events)
        assertEquals(3, incidents.size)
    }

    @Test
    fun `resolveAll uses app knowledge per package`() {
        val events = listOf(
            makeEvent(EventType.DROPPER_PATTERN, pkg = "com.evil.dropper")
        )
        val knowledge = mapOf(
            "com.evil.dropper" to makeApp(
                packageName = "com.evil.dropper",
                trustScore = 10,
                trustLevel = TrustEvidenceEngine.TrustLevel.ANOMALOUS,
                installerType = TrustEvidenceEngine.InstallerType.SIDELOADED
            )
        )

        val incidents = resolver.resolveAll(events, knowledge)
        assertEquals(1, incidents.size)

        // Should have boosted confidence due to low trust + sideload
        val topConf = incidents.first().hypotheses.first().confidence
        assertTrue("App knowledge should boost confidence", topConf > 0.7)
    }

    // ══════════════════════════════════════════════════════════
    //  9. Hypotheses are sorted by confidence descending
    // ══════════════════════════════════════════════════════════

    @Test
    fun `hypotheses sorted by confidence descending`() {
        val event = makeEvent(EventType.OVERLAY_ATTACK_PATTERN)
        val incident = resolver.resolve(event)

        val confidences = incident.hypotheses.map { it.confidence }
        assertEquals(confidences, confidences.sortedDescending())
    }

    // ══════════════════════════════════════════════════════════
    //  10. Confidence is always bounded [0, 1]
    // ══════════════════════════════════════════════════════════

    @Test
    fun `confidence is bounded 0 to 1`() {
        val event = makeEvent(EventType.STAGED_PAYLOAD)
        val appExtreme = makeApp(
            trustScore = 5,
            trustLevel = TrustEvidenceEngine.TrustLevel.ANOMALOUS,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            isNewApp = true,
            activeHighRiskClusters = listOf(TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES)
        )

        val incident = resolver.resolve(event, appExtreme)
        incident.hypotheses.forEach { h ->
            assertTrue("Confidence should be >= 0", h.confidence >= 0.0)
            assertTrue("Confidence should be <= 1", h.confidence <= 1.0)
        }
    }
}
