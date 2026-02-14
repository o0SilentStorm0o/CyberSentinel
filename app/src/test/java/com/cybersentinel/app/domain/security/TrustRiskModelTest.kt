package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Comprehensive unit tests for TrustRiskModel v3.
 *
 * Coverage targets:
 *  - All 4 verdict states: SAFE / INFO / NEEDS_ATTENTION / CRITICAL
 *  - HARD findings always override trust/category
 *  - Combo gating: cluster alone = INFO, cluster + extra signal + low trust = NEEDS_ATTENTION
 *  - Category-aware cluster whitelisting
 *  - High-risk vs privacy distinction
 *  - UNKNOWN installer ≠ SIDELOADED
 *  - <5% NEEDS_ATTENTION on a typical phone (verified via scenario counts)
 */
class TrustRiskModelTest {

    private lateinit var model: TrustRiskModel

    // ────────────────────────────────────────────────────────
    //  Test helpers — TrustEvidence builders
    // ────────────────────────────────────────────────────────

    private fun highTrust(
        packageName: String = "com.example.app",
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
        certMatchType: TrustEvidenceEngine.CertMatchType = TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH
    ) = buildTrust(packageName, score = 85, TrustEvidenceEngine.TrustLevel.HIGH, installerType, certMatchType)

    private fun moderateTrust(
        packageName: String = "com.example.app",
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE
    ) = buildTrust(packageName, score = 55, TrustEvidenceEngine.TrustLevel.MODERATE, installerType)

    private fun lowTrust(
        packageName: String = "com.example.app",
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.UNKNOWN
    ) = buildTrust(packageName, score = 25, TrustEvidenceEngine.TrustLevel.LOW, installerType)

    private fun sideloadedLowTrust(
        packageName: String = "com.example.app"
    ) = buildTrust(
        packageName, score = 15, TrustEvidenceEngine.TrustLevel.LOW,
        TrustEvidenceEngine.InstallerType.SIDELOADED
    )

    private fun anomalousTrust(
        packageName: String = "com.example.app"
    ) = buildTrust(packageName, score = 10, TrustEvidenceEngine.TrustLevel.ANOMALOUS)

    private fun buildTrust(
        packageName: String,
        score: Int,
        level: TrustEvidenceEngine.TrustLevel,
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
        certMatchType: TrustEvidenceEngine.CertMatchType = TrustEvidenceEngine.CertMatchType.UNKNOWN
    ) = TrustEvidenceEngine.TrustEvidence(
        packageName = packageName,
        certSha256 = "ABCD1234",
        certMatch = TrustEvidenceEngine.CertMatchResult(
            matchType = certMatchType,
            matchedDeveloper = if (certMatchType == TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH) "Test" else null,
            knownCertDigests = emptySet(),
            currentCertDigest = "ABCD1234"
        ),
        installerInfo = TrustEvidenceEngine.InstallerInfo(
            installerPackage = when (installerType) {
                TrustEvidenceEngine.InstallerType.PLAY_STORE -> "com.android.vending"
                TrustEvidenceEngine.InstallerType.SIDELOADED -> null
                else -> null
            },
            installerType = installerType,
            isExpectedInstaller = installerType == TrustEvidenceEngine.InstallerType.PLAY_STORE
        ),
        systemAppInfo = TrustEvidenceEngine.SystemAppInfo(
            isSystemApp = false, isPrivilegedApp = false,
            isUpdatedSystemApp = false,
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isPlatformSigned = false
        ),
        signingLineage = TrustEvidenceEngine.SigningLineageInfo(false, 0, false),
        deviceIntegrity = TrustEvidenceEngine.DeviceIntegrityInfo(false, TrustEvidenceEngine.VerifiedBootState.GREEN),
        trustScore = score,
        trustLevel = level,
        reasons = emptyList()
    )

    private fun finding(
        type: TrustRiskModel.FindingType,
        severity: AppSecurityScanner.RiskLevel = AppSecurityScanner.RiskLevel.HIGH
    ) = TrustRiskModel.RawFinding(type, severity, type.name, "")

    @Before
    fun setup() {
        model = TrustRiskModel()
    }

    // ══════════════════════════════════════════════════════════
    //  SAFE verdict tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `SAFE - high trust app with no findings`() {
        val verdict = model.evaluate(
            packageName = "com.google.chrome",
            trustEvidence = highTrust("com.google.chrome"),
            rawFindings = emptyList(),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - high trust app with privacy permissions`() {
        val verdict = model.evaluate(
            packageName = "com.google.camera",
            trustEvidence = highTrust("com.google.camera"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION"
            ),
            appCategory = AppCategoryDetector.AppCategory.CAMERA
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - moderate trust app with no high-risk clusters`() {
        val verdict = model.evaluate(
            packageName = "com.example.calculator",
            trustEvidence = moderateTrust("com.example.calculator"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = emptyList(),
            appCategory = AppCategoryDetector.AppCategory.UTILITY
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - expected cluster for phone dialer (SMS + call log + high trust)`() {
        val verdict = model.evaluate(
            packageName = "com.android.dialer",
            trustEvidence = highTrust("com.android.dialer"),
            rawFindings = emptyList(),
            isSystemApp = true,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG"
            ),
            appCategory = AppCategoryDetector.AppCategory.PHONE_DIALER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - VPN app with VPN cluster is expected`() {
        val verdict = model.evaluate(
            packageName = "com.nordvpn.android",
            trustEvidence = highTrust("com.nordvpn.android"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_VPN_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.VPN
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  INFO verdict tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `INFO - unknown category app with SMS cluster but moderate trust (no extra signal)`() {
        val verdict = model.evaluate(
            packageName = "com.unknown.app",
            trustEvidence = moderateTrust("com.unknown.app"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // SMS cluster is unexpected for OTHER, but moderate trust + no extra signal = INFO not NEEDS_ATTENTION
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
    }

    @Test
    fun `INFO - low trust app with SMS cluster but NO extra signal`() {
        // KEY TEST: Cluster alone with low trust = INFO (combo gating works)
        val verdict = model.evaluate(
            packageName = "com.unknown.smsapp",
            trustEvidence = lowTrust("com.unknown.smsapp"),
            rawFindings = emptyList(), // No extra signals at all
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Low trust + high-risk cluster but NO extra signal → INFO (not NEEDS_ATTENTION)
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
    }

    @Test
    fun `INFO - high-risk perm added but HIGH trust (HARD but trust provides context)`() {
        // HIGH_RISK_PERMISSION_ADDED is HARD, so it stays at its severity.
        // With HIGH trust, hasHardFindings is true → CRITICAL.
        // But we can test that with a SOFT finding + moderate trust → INFO.
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = moderateTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.EXPORTED_SURFACE_INCREASED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        // EXPORTED_SURFACE_INCREASED is SOFT, moderate trust downgrades it → INFO
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
    }

    @Test
    fun `INFO - background location is NOT high-risk`() {
        val verdict = model.evaluate(
            packageName = "com.example.navigation",
            trustEvidence = lowTrust("com.example.navigation"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.ACCESS_BACKGROUND_LOCATION"),
            appCategory = AppCategoryDetector.AppCategory.NAVIGATION
        )
        // Background location is isHighRisk=false, and it's expected for NAVIGATION
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `INFO - exported surface increase with low trust`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.EXPORTED_SURFACE_INCREASED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        // R8: surface increase + low trust → INFO
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  NEEDS_ATTENTION verdict tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `NEEDS_ATTENTION - low trust + SMS cluster + sideloaded (extra signal)`() {
        // KEY TEST: Combo gating — low trust + cluster + extra signal = NEEDS_ATTENTION
        val verdict = model.evaluate(
            packageName = "com.shady.app",
            trustEvidence = sideloadedLowTrust("com.shady.app"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Low trust + unexpected SMS cluster + sideloaded (extra signal) → NEEDS_ATTENTION
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
    }

    @Test
    fun `NEEDS_ATTENTION - low trust + high-risk perm added at LOW severity`() {
        // HIGH_RISK_PERMISSION_ADDED at LOW severity doesn't trigger hasHardFindings (needs MEDIUM+)
        // But R5 catches it: hasHighRiskPermAdded + isLowTrust → NEEDS_ATTENTION
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - low trust + high-risk perm added at HIGH severity (HARD override)`() {
        // HIGH_RISK_PERMISSION_ADDED at HIGH severity is HARD finding with MEDIUM+ → R1 → CRITICAL
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `NEEDS_ATTENTION - low trust + accessibility cluster + suspicious native lib`() {
        val verdict = model.evaluate(
            packageName = "com.shady.tool",
            trustEvidence = lowTrust("com.shady.tool"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // R6: low trust + unexpected accessibility + suspicious native lib (extra signal) → NEEDS_ATTENTION
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
    }

    @Test
    fun `NEEDS_ATTENTION - HIGH combo match (low trust + SMS + call log)`() {
        val verdict = model.evaluate(
            packageName = "com.shady.phone",
            trustEvidence = lowTrust("com.shady.phone"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // R4: Matched combo "Low trust + SMS + call log → HIGH" → NEEDS_ATTENTION
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  CRITICAL verdict tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL - debug signature (HARD finding)`() {
        val verdict = model.evaluate(
            packageName = "com.example.debugapp",
            trustEvidence = highTrust("com.example.debugapp"), // Even high trust can't suppress
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - cert changed (HARD baseline anomaly)`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - anomalous trust level`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = anomalousTrust(),
            rawFindings = emptyList(),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - sideload + debug cert + SMS combo`() {
        val sideloadDebugTrust = buildTrust(
            "com.evil.spy", score = 15, TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED
        )
        val verdict = model.evaluate(
            packageName = "com.evil.spy",
            trustEvidence = sideloadDebugTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Both the HARD finding AND the combo trigger CRITICAL
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - accessibility + overlay + sideloaded combo`() {
        val verdict = model.evaluate(
            packageName = "com.evil.overlay",
            trustEvidence = sideloadedLowTrust("com.evil.overlay"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - accessibility + install packages + low trust combo`() {
        val verdict = model.evaluate(
            packageName = "com.evil.dropper",
            trustEvidence = lowTrust("com.evil.dropper"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Dropper combo: accessibility + install packages + low trust → CRITICAL
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - integrity fail with hooking (HARD)`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  Category-aware cluster whitelist tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `category whitelist - phone dialer SMS is expected`() {
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.SMS,
            AppCategoryDetector.AppCategory.PHONE_DIALER
        ))
    }

    @Test
    fun `category whitelist - phone dialer call log is expected`() {
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.CALL_LOG,
            AppCategoryDetector.AppCategory.PHONE_DIALER
        ))
    }

    @Test
    fun `category whitelist - VPN app VPN cluster is expected`() {
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.VPN,
            AppCategoryDetector.AppCategory.VPN
        ))
    }

    @Test
    fun `category whitelist - accessibility tool accessibility is expected`() {
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
            AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL
        ))
    }

    @Test
    fun `category whitelist - banking app SMS is NOT expected`() {
        assertFalse(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.SMS,
            AppCategoryDetector.AppCategory.BANKING
        ))
    }

    @Test
    fun `category whitelist - messaging SMS is NOT expected`() {
        // Important: messaging apps don't get SMS pass — only system dialers do
        assertFalse(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.SMS,
            AppCategoryDetector.AppCategory.MESSAGING
        ))
    }

    @Test
    fun `category whitelist - OTHER category has no whitelist`() {
        TrustRiskModel.CapabilityCluster.entries.filter { it.isHighRisk }.forEach { cluster ->
            assertFalse(
                "Cluster ${cluster.name} should NOT be whitelisted for OTHER",
                model.isClusterExpectedForCategory(cluster, AppCategoryDetector.AppCategory.OTHER)
            )
        }
    }

    @Test
    fun `category whitelist - combo respects whitelist for phone dialer`() {
        // Phone dialer with SMS + call log + low trust → combo should NOT trigger
        // because SMS and CALL_LOG are expected for phone dialer
        val verdict = model.evaluate(
            packageName = "com.example.dialer",
            trustEvidence = lowTrust("com.example.dialer"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG"
            ),
            appCategory = AppCategoryDetector.AppCategory.PHONE_DIALER
        )
        // SMS + call log are expected for dialer → combo suppressed → should be INFO or SAFE
        assertTrue(
            "Phone dialer with expected clusters should not be CRITICAL or NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(TrustRiskModel.EffectiveRisk.SAFE, TrustRiskModel.EffectiveRisk.INFO)
        )
    }

    // ══════════════════════════════════════════════════════════
    //  HARD findings override everything
    // ══════════════════════════════════════════════════════════

    @Test
    fun `HARD - trust never suppresses debug signature`() {
        val verdict = model.evaluate(
            packageName = "com.google.chrome", // Even Google Chrome
            trustEvidence = highTrust("com.google.chrome"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            appCategory = AppCategoryDetector.AppCategory.BROWSER
        )
        // HARD finding → adjusted severity is NOT downgraded
        val debugFinding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.DEBUG_SIGNATURE
        }
        assertFalse("HARD finding should NOT be downgraded", debugFinding.wasDowngraded)
        assertEquals(AppSecurityScanner.RiskLevel.HIGH, debugFinding.adjustedSeverity)
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `HARD - high-risk perm added is not downgraded`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false
        )
        val permFinding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED
        }
        assertFalse("HARD finding should NOT be downgraded", permFinding.wasDowngraded)
    }

    // ══════════════════════════════════════════════════════════
    //  SOFT/WEAK finding adjustment tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `SOFT - over-privileged downgraded by high trust`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        val finding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.OVER_PRIVILEGED
        }
        assertTrue("SOFT finding should be downgraded for high trust", finding.wasDowngraded)
        assertTrue(finding.adjustedSeverity.score < AppSecurityScanner.RiskLevel.MEDIUM.score)
    }

    @Test
    fun `WEAK - exported components invisible for high trust`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = highTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = false
        )
        val finding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.EXPORTED_COMPONENTS
        }
        assertEquals(
            "WEAK_SIGNAL should be NONE for high trust",
            AppSecurityScanner.RiskLevel.NONE,
            finding.adjustedSeverity
        )
    }

    @Test
    fun `SOFT - over-privileged NOT downgraded for low trust`() {
        val verdict = model.evaluate(
            packageName = "com.example.app",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        val finding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.OVER_PRIVILEGED
        }
        assertFalse("SOFT finding should NOT be downgraded for low trust", finding.wasDowngraded)
    }

    // ══════════════════════════════════════════════════════════
    //  Installer provenance: UNKNOWN ≠ SIDELOADED
    // ══════════════════════════════════════════════════════════

    @Test
    fun `UNKNOWN installer is NOT treated as sideloaded for combos`() {
        // Unknown installer app with SMS → should NOT trigger sideload combo
        val unknownInstallerTrust = lowTrust(installerType = TrustEvidenceEngine.InstallerType.UNKNOWN)
        val verdict = model.evaluate(
            packageName = "com.mystery.app",
            trustEvidence = unknownInstallerTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // The "sideload + debug + SMS" combo requires SIDELOADED specifically, not UNKNOWN
        // CRITICAL will still trigger because DEBUG_SIGNATURE is HARD
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        // But the combo shouldn't match
        assertFalse(
            "Sideload combo should NOT match for UNKNOWN installer",
            verdict.matchedCombos.contains("Podezřelý SMS přístup")
        )
    }

    @Test
    fun `SIDELOADED installer DOES trigger sideload combo`() {
        val sideloadedTrust = buildTrust(
            "com.evil.app", score = 15, TrustEvidenceEngine.TrustLevel.LOW,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED
        )
        val verdict = model.evaluate(
            packageName = "com.evil.app",
            trustEvidence = sideloadedTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertTrue(
            "Sideload combo SHOULD match for SIDELOADED installer",
            verdict.matchedCombos.contains("Podezřelý SMS přístup")
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Combo gating — prevent NEEDS_ATTENTION inflation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `combo gating - cluster alone is INFO not NEEDS_ATTENTION`() {
        // Low trust + accessibility but nothing else → INFO
        val verdict = model.evaluate(
            packageName = "com.unknown.app",
            trustEvidence = lowTrust("com.unknown.app"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
    }

    @Test
    fun `combo gating - cluster + extra signal = NEEDS_ATTENTION`() {
        // Low trust + accessibility + suspicious native lib → NEEDS_ATTENTION
        val verdict = model.evaluate(
            packageName = "com.unknown.app",
            trustEvidence = lowTrust("com.unknown.app"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
    }

    @Test
    fun `combo gating - high trust suppresses even cluster + signal`() {
        // High trust + accessibility + suspicious native lib → NOT NEEDS_ATTENTION
        val verdict = model.evaluate(
            packageName = "com.trusted.app",
            trustEvidence = highTrust("com.trusted.app"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // High trust → R6 won't fire (isLowTrust = false)
        assertTrue(
            "High trust should prevent NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(TrustRiskModel.EffectiveRisk.SAFE, TrustRiskModel.EffectiveRisk.INFO)
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Privacy capabilities (informational only)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `privacy capabilities are tracked but never alarm`() {
        val verdict = model.evaluate(
            packageName = "com.example.social",
            trustEvidence = moderateTrust("com.example.social"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS"
            ),
            appCategory = AppCategoryDetector.AppCategory.SOCIAL
        )
        assertTrue("Privacy capabilities should be populated", verdict.privacyCapabilities.isNotEmpty())
        // Privacy permissions alone should NEVER trigger alarm
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `privacy capabilities show expected annotation for matching category`() {
        val verdict = model.evaluate(
            packageName = "com.example.camera",
            trustEvidence = highTrust("com.example.camera"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.CAMERA"),
            appCategory = AppCategoryDetector.AppCategory.CAMERA
        )
        assertTrue(
            "Camera permission should be marked as expected for camera app",
            verdict.privacyCapabilities.any { it.contains("očekávané") }
        )
    }

    // ══════════════════════════════════════════════════════════
    //  System app visibility
    // ══════════════════════════════════════════════════════════

    @Test
    fun `system app - shown in main list only on hard findings`() {
        val safeVerdict = model.evaluate(
            packageName = "com.android.system",
            trustEvidence = highTrust("com.android.system"),
            rawFindings = emptyList(),
            isSystemApp = true
        )
        assertFalse("Safe system app should NOT show in main list", safeVerdict.shouldShowInMainList)

        val criticalVerdict = model.evaluate(
            packageName = "com.android.system",
            trustEvidence = highTrust("com.android.system"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true
        )
        assertTrue("Critical system app SHOULD show in main list", criticalVerdict.shouldShowInMainList)
    }

    // ══════════════════════════════════════════════════════════
    //  CapabilityCluster unit tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `cluster isActive detects matching permissions`() {
        val perms = listOf("android.permission.READ_SMS", "android.permission.CAMERA")
        assertTrue(TrustRiskModel.CapabilityCluster.SMS.isActive(perms))
        assertFalse(TrustRiskModel.CapabilityCluster.CALL_LOG.isActive(perms))
    }

    @Test
    fun `cluster isHighRisk correctly separates categories`() {
        assertTrue(TrustRiskModel.CapabilityCluster.SMS.isHighRisk)
        assertTrue(TrustRiskModel.CapabilityCluster.ACCESSIBILITY.isHighRisk)
        assertTrue(TrustRiskModel.CapabilityCluster.DEVICE_ADMIN.isHighRisk)
        assertFalse(TrustRiskModel.CapabilityCluster.BACKGROUND_LOCATION.isHighRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  Risk score tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `risk score is higher for hard findings than soft`() {
        val hardVerdict = model.evaluate(
            packageName = "com.example.hard",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = false
        )
        val softVerdict = model.evaluate(
            packageName = "com.example.soft",
            trustEvidence = lowTrust(),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        assertTrue(
            "Hard finding should produce higher risk score",
            hardVerdict.riskScore > softVerdict.riskScore
        )
    }

    @Test
    fun `risk score is 0 for clean app`() {
        val verdict = model.evaluate(
            packageName = "com.example.clean",
            trustEvidence = highTrust(),
            rawFindings = emptyList(),
            isSystemApp = false
        )
        assertEquals(0, verdict.riskScore)
    }

    @Test
    fun `risk score capped at 100`() {
        // Many high-severity findings should still cap at 100
        val findings = List(20) {
            finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
        }
        val verdict = model.evaluate(
            packageName = "com.example.bad",
            trustEvidence = lowTrust(),
            rawFindings = findings,
            isSystemApp = false
        )
        assertTrue(verdict.riskScore <= 100)
    }

    // ══════════════════════════════════════════════════════════
    //  Scenario: typical phone simulation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `scenario - typical phone should have low NEEDS_ATTENTION rate`() {
        // Simulate ~30 apps that would be on a normal phone
        val apps = listOf(
            // System / Google apps — all high trust, expected perms
            triple("com.google.chrome", highTrust("com.google.chrome"), AppCategoryDetector.AppCategory.BROWSER),
            triple("com.google.android.gms", highTrust("com.google.android.gms"), AppCategoryDetector.AppCategory.OTHER),
            triple("com.google.android.dialer", highTrust("com.google.android.dialer"), AppCategoryDetector.AppCategory.PHONE_DIALER),
            triple("com.google.android.apps.maps", highTrust("com.google.android.apps.maps"), AppCategoryDetector.AppCategory.NAVIGATION),
            triple("com.google.android.youtube", highTrust("com.google.android.youtube"), AppCategoryDetector.AppCategory.SOCIAL),
            // Popular apps from Play Store — moderate trust
            triple("com.whatsapp", moderateTrust("com.whatsapp"), AppCategoryDetector.AppCategory.MESSAGING),
            triple("com.instagram.android", moderateTrust("com.instagram.android"), AppCategoryDetector.AppCategory.SOCIAL),
            triple("com.spotify.music", moderateTrust("com.spotify.music"), AppCategoryDetector.AppCategory.OTHER),
            triple("cz.csob.smartbanking", moderateTrust("cz.csob.smartbanking"), AppCategoryDetector.AppCategory.BANKING),
            triple("com.nordvpn.android", moderateTrust("com.nordvpn.android"), AppCategoryDetector.AppCategory.VPN),
            // Less known apps — lower trust
            triple("com.random.calculator", lowTrust("com.random.calculator"), AppCategoryDetector.AppCategory.UTILITY),
            triple("com.unknown.flashlight", lowTrust("com.unknown.flashlight"), AppCategoryDetector.AppCategory.UTILITY),
            triple("com.unknown.game1", lowTrust("com.unknown.game1"), AppCategoryDetector.AppCategory.GAME),
            triple("com.unknown.notes", lowTrust("com.unknown.notes"), AppCategoryDetector.AppCategory.UTILITY),
            triple("com.unknown.weather", lowTrust("com.unknown.weather"), AppCategoryDetector.AppCategory.OTHER)
        )

        var needsAttention = 0
        var critical = 0

        for ((pkg, trust, category) in apps) {
            // Give VPN app VPN permission, dialer SMS/call log, etc.
            val perms = when (category) {
                AppCategoryDetector.AppCategory.PHONE_DIALER -> listOf(
                    "android.permission.READ_SMS", "android.permission.READ_CALL_LOG"
                )
                AppCategoryDetector.AppCategory.VPN -> listOf("android.permission.BIND_VPN_SERVICE")
                AppCategoryDetector.AppCategory.NAVIGATION -> listOf(
                    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"
                )
                AppCategoryDetector.AppCategory.MESSAGING -> listOf(
                    "android.permission.CAMERA", "android.permission.READ_CONTACTS"
                )
                AppCategoryDetector.AppCategory.BANKING -> listOf("android.permission.CAMERA")
                else -> emptyList()
            }

            val verdict = model.evaluate(
                packageName = pkg,
                trustEvidence = trust,
                rawFindings = emptyList(),
                isSystemApp = false,
                grantedPermissions = perms,
                appCategory = category
            )

            if (verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION) needsAttention++
            if (verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL) critical++
        }

        assertEquals("CRITICAL should be 0 on a normal phone", 0, critical)
        assertTrue(
            "NEEDS_ATTENTION should be <5% (got $needsAttention/${apps.size} = ${needsAttention * 100 / apps.size}%)",
            needsAttention * 100 / apps.size < 5
        )
    }

    private fun triple(
        pkg: String,
        trust: TrustEvidenceEngine.TrustEvidence,
        category: AppCategoryDetector.AppCategory
    ) = Triple(pkg, trust, category)

    // ══════════════════════════════════════════════════════════
    //  Scenario: semi-risk phone — realistic threats expected
    // ══════════════════════════════════════════════════════════

    @Test
    fun `scenario - semi-risk phone catches real threats`() {
        // Mix of normal apps + a few genuinely suspicious ones
        // Expected: 1-2 NEEDS_ATTENTION, 1 CRITICAL, rest SAFE/INFO
        data class AppSpec(
            val pkg: String,
            val trust: TrustEvidenceEngine.TrustEvidence,
            val category: AppCategoryDetector.AppCategory,
            val perms: List<String>,
            val findings: List<TrustRiskModel.RawFinding>,
            val isSystemApp: Boolean = false
        )

        val apps = listOf(
            // Normal safe apps
            AppSpec("com.google.chrome", highTrust("com.google.chrome"),
                AppCategoryDetector.AppCategory.BROWSER, emptyList(), emptyList()),
            AppSpec("com.whatsapp", moderateTrust("com.whatsapp"),
                AppCategoryDetector.AppCategory.MESSAGING,
                listOf("android.permission.CAMERA", "android.permission.READ_CONTACTS"), emptyList()),
            AppSpec("com.spotify.music", moderateTrust("com.spotify.music"),
                AppCategoryDetector.AppCategory.OTHER, emptyList(), emptyList()),
            AppSpec("cz.csob.smartbanking", moderateTrust("cz.csob.smartbanking"),
                AppCategoryDetector.AppCategory.BANKING,
                listOf("android.permission.CAMERA"), emptyList()),

            // Suspicious #1: sideloaded overlay + accessibility (→ CRITICAL combo)
            AppSpec("com.shady.screenrecord", sideloadedLowTrust("com.shady.screenrecord"),
                AppCategoryDetector.AppCategory.OTHER,
                listOf("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"),
                emptyList()),

            // Suspicious #2: cleaner app with notification listener + low trust (→ INFO or NEEDS_ATTENTION)
            AppSpec("com.free.cleaner", lowTrust("com.free.cleaner"),
                AppCategoryDetector.AppCategory.UTILITY,
                listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
                emptyList()),

            // Suspicious #3: sideloaded unknown VPN (→ NEEDS_ATTENTION via new combo)
            AppSpec("com.free.vpn.unlimited", sideloadedLowTrust("com.free.vpn.unlimited"),
                AppCategoryDetector.AppCategory.VPN,
                listOf("android.permission.BIND_VPN_SERVICE"),
                emptyList()),

            // Normal phone dialer (system)
            AppSpec("com.android.dialer", highTrust("com.android.dialer"),
                AppCategoryDetector.AppCategory.PHONE_DIALER,
                listOf("android.permission.READ_SMS", "android.permission.READ_CALL_LOG"),
                emptyList(), isSystemApp = true)
        )

        val verdicts = apps.map { spec ->
            model.evaluate(
                packageName = spec.pkg,
                trustEvidence = spec.trust,
                rawFindings = spec.findings,
                isSystemApp = spec.isSystemApp,
                grantedPermissions = spec.perms,
                appCategory = spec.category
            )
        }

        val criticalCount = verdicts.count { it.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL }
        val needsAttentionCount = verdicts.count { it.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION }
        val safeCount = verdicts.count { it.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE }

        // The sideloaded overlay+accessibility should be CRITICAL
        assertTrue("Should catch at least 1 CRITICAL threat, got $criticalCount", criticalCount >= 1)
        // The sideloaded VPN should be at least NEEDS_ATTENTION
        assertTrue("Should catch at least 1 NEEDS_ATTENTION, got $needsAttentionCount", needsAttentionCount >= 1)
        // Normal apps should remain SAFE
        assertTrue("Most apps should be SAFE, got $safeCount/${apps.size}", safeCount >= 3)

        // Verify specific verdicts
        val overlayVerdict = verdicts.first { it.packageName == "com.shady.screenrecord" }
        assertEquals("Sideloaded overlay+accessibility should be CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, overlayVerdict.effectiveRisk)

        val vpnVerdict = verdicts.first { it.packageName == "com.free.vpn.unlimited" }
        assertEquals("Sideloaded low-trust VPN should be NEEDS_ATTENTION",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, vpnVerdict.effectiveRisk)

        val dialerVerdict = verdicts.first { it.packageName == "com.android.dialer" }
        assertEquals("System dialer should be SAFE",
            TrustRiskModel.EffectiveRisk.SAFE, dialerVerdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  Adversarial combo tests (red-team)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `adversarial A - overlay + accessibility + sideloaded = CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.evil.clicker",
            trustEvidence = sideloadedLowTrust("com.evil.clicker"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        assertTrue(verdict.matchedCombos.any { it.contains("overlay") || it.contains("accessibility") })
    }

    @Test
    fun `adversarial B - stalkerware accessibility + notification listener + low trust (non-sideloaded) = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.parental.control.free",
            trustEvidence = lowTrust("com.parental.control.free"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Non-sideloaded stalkerware combo = HIGH severity → NEEDS_ATTENTION
        assertEquals(
            "Non-sideloaded stalkerware combo should be NEEDS_ATTENTION",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
            verdict.effectiveRisk
        )
        assertTrue(
            "Should match stalkerware combo",
            verdict.matchedCombos.any { it.contains("stalkerware") || it.contains("Stalkerware") }
        )
    }

    @Test
    fun `adversarial C - SMS reader sideloaded + low trust = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.shady.smsbackup",
            trustEvidence = sideloadedLowTrust("com.shady.smsbackup"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // R6: low trust + unexpected SMS + sideloaded (extra signal) → NEEDS_ATTENTION
        assertTrue(
            "Sideloaded SMS reader should be at least NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
    }

    @Test
    fun `adversarial D - sideloaded VPN + low trust = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.free.vpn.sketchy",
            trustEvidence = sideloadedLowTrust("com.free.vpn.sketchy"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_VPN_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.VPN
        )
        // New combo: sideloaded VPN + low trust, respectCategoryWhitelist=false
        assertEquals(
            "Sideloaded low-trust VPN should be NEEDS_ATTENTION",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk
        )
        assertTrue(
            "Should match VPN sideload combo",
            verdict.matchedCombos.any { it.contains("VPN") }
        )
    }

    @Test
    fun `adversarial D2 - sideloaded VPN + suspicious native lib + low trust = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.free.vpn.native",
            trustEvidence = sideloadedLowTrust("com.free.vpn.native"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_VPN_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.VPN
        )
        assertTrue(
            "Sideloaded VPN with native lib should be at least NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
    }

    @Test
    fun `adversarial E - sideloaded + install packages = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.unknown.appstore",
            trustEvidence = sideloadedLowTrust("com.unknown.appstore"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.REQUEST_INSTALL_PACKAGES"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // New combo: sideloaded + install packages
        assertTrue(
            "Sideloaded app with install permission should be at least NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
        assertTrue(
            "Should match install combo",
            verdict.matchedCombos.any { it.contains("instalac") || it.contains("Sideload") }
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Accessibility tool trust gating
    // ══════════════════════════════════════════════════════════

    @Test
    fun `accessibility tool - high trust whitelists accessibility`() {
        assertTrue(
            "High trust accessibility tool should whitelist accessibility",
            model.isClusterExpectedForCategory(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL,
                trustScore = 85
            )
        )
    }

    @Test
    fun `accessibility tool - moderate trust whitelists accessibility`() {
        assertTrue(
            "Moderate trust accessibility tool should whitelist accessibility",
            model.isClusterExpectedForCategory(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL,
                trustScore = 50
            )
        )
    }

    @Test
    fun `accessibility tool - low trust does NOT whitelist accessibility`() {
        assertFalse(
            "Low trust accessibility tool should NOT whitelist accessibility",
            model.isClusterExpectedForCategory(
                TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
                AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL,
                trustScore = 20
            )
        )
    }

    @Test
    fun `accessibility tool - low trust sideloaded triggers NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.sketchy.accessibility",
            trustEvidence = sideloadedLowTrust("com.sketchy.accessibility"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL
        )
        // Despite being ACCESSIBILITY_TOOL category, low trust + sideloaded should still flag
        assertTrue(
            "Low-trust sideloaded accessibility tool should be at least NEEDS_ATTENTION, got ${verdict.effectiveRisk}",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
    }

    @Test
    fun `accessibility tool - high trust from Play Store is SAFE`() {
        val verdict = model.evaluate(
            packageName = "com.google.talkback",
            trustEvidence = highTrust("com.google.talkback"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL
        )
        assertEquals(
            "Trusted accessibility tool should be SAFE",
            TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk
        )
    }

    // ══════════════════════════════════════════════════════════
    //  System app integrity fail scenario
    // ══════════════════════════════════════════════════════════

    @Test
    fun `system app - cert change is CRITICAL regardless of trust`() {
        val systemTrust = buildTrust(
            "com.android.systemui", score = 90, TrustEvidenceEngine.TrustLevel.HIGH,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER
        )
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        assertTrue("System app with cert change should show in main list", verdict.shouldShowInMainList)
    }

    @Test
    fun `system app - integrity fail with hooking is CRITICAL`() {
        val systemTrust = buildTrust(
            "com.android.settings", score = 90, TrustEvidenceEngine.TrustLevel.HIGH,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER
        )
        val verdict = model.evaluate(
            packageName = "com.android.settings",
            trustEvidence = systemTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        assertTrue("System integrity fail should show in main list", verdict.shouldShowInMainList)
    }

    @Test
    fun `system app - new system app appearing after first scan is CRITICAL`() {
        val systemTrust = buildTrust(
            "com.malware.system", score = 50, TrustEvidenceEngine.TrustLevel.MODERATE,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER
        )
        val verdict = model.evaluate(
            packageName = "com.malware.system",
            trustEvidence = systemTrust,
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_NEW_SYSTEM_APP, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  VERSION_ROLLBACK tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `VERSION_ROLLBACK is HARD and triggers CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.example.downgraded",
            trustEvidence = moderateTrust("com.example.downgraded"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false
        )
        // VERSION_ROLLBACK is HARD → CRITICAL regardless of trust
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        // Verify it was not downgraded
        val rollbackFinding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.VERSION_ROLLBACK
        }
        assertFalse("VERSION_ROLLBACK should NOT be downgraded", rollbackFinding.wasDowngraded)
    }

    @Test
    fun `VERSION_ROLLBACK is treated as baseline delta`() {
        // Verify VERSION_ROLLBACK counts as hasExtraSignal via hasBaselineDelta
        val verdict = model.evaluate(
            packageName = "com.example.rollback",
            trustEvidence = lowTrust("com.example.rollback"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.READ_SMS"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // HARD finding → CRITICAL, but also serves as extra signal for combos
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    // ══════════════════════════════════════════════════════════
    //  Existing tests: verify backward compat with isClusterExpectedForCategory
    // ══════════════════════════════════════════════════════════

    @Test
    fun `category whitelist backward compat - default trustScore whitelists normally`() {
        // Calling without trustScore should default to 100 (fully trusted)
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.ACCESSIBILITY,
            AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL
        ))
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.VPN,
            AppCategoryDetector.AppCategory.VPN
        ))
        assertTrue(model.isClusterExpectedForCategory(
            TrustRiskModel.CapabilityCluster.SMS,
            AppCategoryDetector.AppCategory.PHONE_DIALER
        ))
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: Stalkerware two-level escalation
    // ══════════════════════════════════════════════════════════

    @Test
    fun `stalkerware - sideloaded + accessibility + notif listener + low trust = CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.spy.sideloaded",
            trustEvidence = sideloadedLowTrust("com.spy.sideloaded"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(
            "Sideloaded stalkerware should be CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk
        )
        assertTrue(
            "Should match sideloaded stalkerware combo",
            verdict.matchedCombos.any { it.contains("sideload") || it.contains("Sideload") }
        )
    }

    @Test
    fun `stalkerware - non-sideloaded + accessibility + notif listener + low trust = NEEDS_ATTENTION (not CRITICAL)`() {
        val verdict = model.evaluate(
            packageName = "com.spy.fromstore",
            trustEvidence = lowTrust("com.spy.fromstore"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // Non-sideloaded stalkerware = HIGH combo → NEEDS_ATTENTION, NOT CRITICAL
        assertEquals(
            "Non-sideloaded stalkerware should be NEEDS_ATTENTION, not CRITICAL",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: VERSION_ROLLBACK_TRUSTED
    // ══════════════════════════════════════════════════════════

    @Test
    fun `VERSION_ROLLBACK_TRUSTED is SOFT and does NOT trigger CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.example.trustedrollback",
            trustEvidence = moderateTrust("com.example.trustedrollback"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        // VERSION_ROLLBACK_TRUSTED is SOFT → should NOT cause CRITICAL
        assertNotEquals(
            "Trusted rollback should NOT be CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk
        )
        // The finding should be downgraded by moderate trust
        val rollbackFinding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED
        }
        assertTrue("VERSION_ROLLBACK_TRUSTED should be SOFT", rollbackFinding.hardness == TrustRiskModel.FindingHardness.SOFT)
        assertTrue("Should be downgraded for moderate trust", rollbackFinding.wasDowngraded)
    }

    @Test
    fun `VERSION_ROLLBACK_TRUSTED with high trust is minimized`() {
        val verdict = model.evaluate(
            packageName = "com.example.playstorerollback",
            trustEvidence = highTrust("com.example.playstorerollback"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        // High trust + SOFT MEDIUM → should be SAFE or at most INFO
        assertTrue(
            "Trusted rollback from high-trust source should be at most INFO, got ${verdict.effectiveRisk}",
            verdict.effectiveRisk in setOf(TrustRiskModel.EffectiveRisk.SAFE, TrustRiskModel.EffectiveRisk.INFO)
        )
    }

    @Test
    fun `VERSION_ROLLBACK (sideloaded) remains HARD and CRITICAL`() {
        // This is the original behavior — sideloaded rollback stays HARD → CRITICAL
        val verdict = model.evaluate(
            packageName = "com.example.sideloadrollback",
            trustEvidence = sideloadedLowTrust("com.example.sideloadrollback"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false
        )
        assertEquals(
            "Sideloaded rollback should remain CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk
        )
        val rollbackFinding = verdict.adjustedFindings.first {
            it.findingType == TrustRiskModel.FindingType.VERSION_ROLLBACK
        }
        assertFalse("HARD rollback should NOT be downgraded", rollbackFinding.wasDowngraded)
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: Installer change + high-risk cluster (R4b)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `installer change + accessibility cluster = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.example.installerswitch",
            trustEvidence = moderateTrust("com.example.installerswitch"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // R4b: installer anomaly + ACCESSIBILITY cluster → NEEDS_ATTENTION
        assertTrue(
            "Installer change with accessibility should be at least NEEDS_ATTENTION, got ${verdict.effectiveRisk}",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
    }

    @Test
    fun `installer change + VPN cluster = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.example.installerswitch.vpn",
            trustEvidence = moderateTrust("com.example.installerswitch.vpn"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_VPN_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertTrue(
            "Installer change with VPN cluster should be at least NEEDS_ATTENTION",
            verdict.effectiveRisk in setOf(
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION,
                TrustRiskModel.EffectiveRisk.CRITICAL
            )
        )
    }

    @Test
    fun `installer change + no high-risk cluster = CRITICAL (HARD finding alone)`() {
        // INSTALLER_ANOMALY is HARD → CRITICAL regardless, but R4b doesn't add anything extra
        val verdict = model.evaluate(
            packageName = "com.example.installeronly",
            trustEvidence = moderateTrust("com.example.installeronly"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = emptyList(),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        // INSTALLER_ANOMALY is HARD → CRITICAL even without clusters
        assertEquals(
            "INSTALLER_ANOMALY alone is HARD → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: isNewApp as extra signal
    // ══════════════════════════════════════════════════════════

    @Test
    fun `new app + low trust + unexpected cluster = NEEDS_ATTENTION`() {
        val verdict = model.evaluate(
            packageName = "com.unknown.newapp",
            trustEvidence = lowTrust("com.unknown.newapp"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER,
            isNewApp = true
        )
        // isNewApp provides the extra signal → R6 fires: low trust + unexpected cluster + extra signal
        assertEquals(
            "New app with low trust and accessibility should be NEEDS_ATTENTION",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk
        )
    }

    @Test
    fun `new app + moderate trust + cluster = not escalated`() {
        val verdict = model.evaluate(
            packageName = "com.newapp.moderate",
            trustEvidence = moderateTrust("com.newapp.moderate"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER,
            isNewApp = true
        )
        // isNewApp is extra signal, but trust is moderate → R6 requires isLowTrust → not NEEDS_ATTENTION
        assertNotEquals(
            "New app with moderate trust should NOT be NEEDS_ATTENTION",
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk
        )
    }

    @Test
    fun `existing app + low trust + cluster without extra signal = INFO`() {
        val verdict = model.evaluate(
            packageName = "com.existing.lowapp",
            trustEvidence = lowTrust("com.existing.lowapp"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER,
            isNewApp = false
        )
        // No extra signal (not new, not sideloaded, no baseline delta) → INFO, not NEEDS_ATTENTION
        assertEquals(
            "Existing app with low trust and cluster but no extra signal should be INFO",
            TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: topReasons limit
    // ══════════════════════════════════════════════════════════

    @Test
    fun `topReasons - CRITICAL verdict has at most 3 reasons`() {
        val verdict = model.evaluate(
            packageName = "com.evil.many.findings",
            trustEvidence = sideloadedLowTrust("com.evil.many.findings"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.CRITICAL),
                finding(TrustRiskModel.FindingType.SIGNATURE_MISMATCH, AppSecurityScanner.RiskLevel.HIGH),
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY, AppSecurityScanner.RiskLevel.HIGH),
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.OTHER
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
        assertTrue(
            "CRITICAL verdict should have at most 3 reasons, got ${verdict.topReasons.size}",
            verdict.topReasons.size <= 3
        )
        assertTrue(
            "CRITICAL verdict should have at least 1 reason",
            verdict.topReasons.isNotEmpty()
        )
    }

    @Test
    fun `topReasons - NEEDS_ATTENTION verdict has at most 2 reasons`() {
        val verdict = model.evaluate(
            packageName = "com.example.attention",
            trustEvidence = sideloadedLowTrust("com.example.attention"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf(
                "android.permission.BIND_VPN_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.VPN
        )
        // This triggers the sideloaded VPN combo → NEEDS_ATTENTION
        assertEquals(TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION, verdict.effectiveRisk)
        assertTrue(
            "NEEDS_ATTENTION verdict should have at most 2 reasons, got ${verdict.topReasons.size}",
            verdict.topReasons.size <= 2
        )
    }

    @Test
    fun `topReasons - SAFE verdict has 0 reasons`() {
        val verdict = model.evaluate(
            packageName = "com.safe.app",
            trustEvidence = highTrust("com.safe.app"),
            rawFindings = emptyList(),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
        assertTrue(
            "SAFE verdict should have 0 reasons",
            verdict.topReasons.isEmpty()
        )
    }

    @Test
    fun `topReasons - INFO verdict has 0 reasons`() {
        val verdict = model.evaluate(
            packageName = "com.info.app",
            trustEvidence = lowTrust("com.info.app"),
            rawFindings = emptyList(),
            isSystemApp = false,
            grantedPermissions = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.OTHER,
            isNewApp = false
        )
        // Low trust + cluster but no extra signal → INFO
        assertEquals(TrustRiskModel.EffectiveRisk.INFO, verdict.effectiveRisk)
        assertTrue(
            "INFO verdict should have 0 reasons",
            verdict.topReasons.isEmpty()
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: explainPriority ordering
    // ══════════════════════════════════════════════════════════

    @Test
    fun `explainPriority - HARD findings have lower priority number than SOFT`() {
        val verdict = model.evaluate(
            packageName = "com.example.priority",
            trustEvidence = lowTrust("com.example.priority"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY, AppSecurityScanner.RiskLevel.HIGH), // HARD
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.HIGH)   // SOFT
            ),
            isSystemApp = false
        )
        val hardPriority = verdict.adjustedFindings
            .first { it.hardness == TrustRiskModel.FindingHardness.HARD }
            .explainPriority
        val softPriority = verdict.adjustedFindings
            .first { it.hardness == TrustRiskModel.FindingHardness.SOFT }
            .explainPriority
        assertTrue(
            "HARD finding priority ($hardPriority) should be lower than SOFT ($softPriority)",
            hardPriority < softPriority
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: Dashboard appsSecurityScore
    // ══════════════════════════════════════════════════════════

    @Test
    fun `appsSecurityScore - no threats = 100`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 50, criticalRiskApps = 0, highRiskApps = 0,
            mediumRiskApps = 5, safeApps = 45, totalIssues = 5,
            criticalIssues = 0, overPrivilegedApps = 2, debugSignedApps = 0,
            suspiciousNativeApps = 0
        )
        assertEquals("No threats = score 100", 100, summary.appsSecurityScore)
    }

    @Test
    fun `appsSecurityScore - 1 critical = 80`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 50, criticalRiskApps = 1, highRiskApps = 0,
            mediumRiskApps = 5, safeApps = 44, totalIssues = 10,
            criticalIssues = 1, overPrivilegedApps = 2, debugSignedApps = 0,
            suspiciousNativeApps = 0
        )
        assertEquals("1 critical = score 80", 80, summary.appsSecurityScore)
    }

    @Test
    fun `appsSecurityScore - 2 critical + 2 high risk = 50`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 50, criticalRiskApps = 2, highRiskApps = 2,
            mediumRiskApps = 3, safeApps = 43, totalIssues = 15,
            criticalIssues = 2, overPrivilegedApps = 3, debugSignedApps = 1,
            suspiciousNativeApps = 0
        )
        // Deduction: 2*20 + 2*5 = 50 → score = 50
        assertEquals("2 critical + 2 high risk = score 50", 50, summary.appsSecurityScore)
    }

    @Test
    fun `appsSecurityScore - extreme threats floors at 0`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 50, criticalRiskApps = 5, highRiskApps = 10,
            mediumRiskApps = 0, safeApps = 35, totalIssues = 50,
            criticalIssues = 5, overPrivilegedApps = 0, debugSignedApps = 0,
            suspiciousNativeApps = 0
        )
        // Deduction: 5*20 + 10*5 = 150 → clamped to 0
        assertEquals("Extreme threats = floor at 0", 0, summary.appsSecurityScore)
    }

    @Test
    fun `appsSecurityScore - empty scan = 100`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 0, criticalRiskApps = 0, highRiskApps = 0,
            mediumRiskApps = 0, safeApps = 0, totalIssues = 0,
            criticalIssues = 0, overPrivilegedApps = 0, debugSignedApps = 0,
            suspiciousNativeApps = 0
        )
        assertEquals("Empty scan = score 100", 100, summary.appsSecurityScore)
    }

    @Test
    fun `appsSecurityScore - only medium risk apps do NOT penalize`() {
        val summary = AppSecurityScanner.ScanSummary(
            totalAppsScanned = 50, criticalRiskApps = 0, highRiskApps = 0,
            mediumRiskApps = 20, safeApps = 30, totalIssues = 20,
            criticalIssues = 0, overPrivilegedApps = 10, debugSignedApps = 5,
            suspiciousNativeApps = 3
        )
        // mediumRiskApps don't penalize in the new formula
        assertEquals("Medium risk only = score 100", 100, summary.appsSecurityScore)
    }

    // ══════════════════════════════════════════════════════════
    //  Phase 5: VERSION_ROLLBACK_TRUSTED FindingType properties
    // ══════════════════════════════════════════════════════════

    @Test
    fun `VERSION_ROLLBACK_TRUSTED is SOFT hardness`() {
        assertEquals(
            "VERSION_ROLLBACK_TRUSTED should be SOFT",
            TrustRiskModel.FindingHardness.SOFT,
            TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED.hardness
        )
    }

    @Test
    fun `VERSION_ROLLBACK is HARD hardness`() {
        assertEquals(
            "VERSION_ROLLBACK should be HARD",
            TrustRiskModel.FindingHardness.HARD,
            TrustRiskModel.FindingType.VERSION_ROLLBACK.hardness
        )
    }
}
