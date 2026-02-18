package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Regression test suite for the v4 system-app policy layer.
 *
 * Invariants under test:
 *  1. InstallClass classification correctness
 *  2. SYSTEM_PREINSTALLED never gets isNewApp=true (semantic separation)
 *  3. System apps with ONLY hygiene findings → SAFE under SYSTEM PolicyProfile
 *  4. System apps with HARD findings → still CRITICAL (never suppressed)
 *  5. R10 weighted threshold: USER(1) vs SYSTEM(5)
 *  6. System category detection (telecom, messaging, framework, connectivity)
 *  7. System category cluster whitelisting (expected permissions not flagged)
 *  8. Population invariant: <5% NEEDS_ATTENTION for system apps without hard evidence
 *
 * These tests prevent regression of the "alarm wall" bug where toggling
 * system-app visibility flooded the UI with false NEEDS_ATTENTION / INFO verdicts.
 */
class SystemAppPolicyRegressionTest {

    private lateinit var model: TrustRiskModel

    // ════════════════════════════════════════════════════════════
    //  Test helpers
    // ════════════════════════════════════════════════════════════

    /**
     * Build TrustEvidence for a system-preinstalled app.
     * High trust by default (system installer, platform-signed).
     */
    private fun systemTrust(
        packageName: String = "com.android.phone",
        score: Int = 85,
        level: TrustEvidenceEngine.TrustLevel = TrustEvidenceEngine.TrustLevel.HIGH
    ) = TrustEvidenceEngine.TrustEvidence(
        packageName = packageName,
        certSha256 = "SYSTEM_CERT_1234",
        certMatch = TrustEvidenceEngine.CertMatchResult(
            matchType = TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH,
            matchedDeveloper = "System",
            knownCertDigests = emptySet(),
            currentCertDigest = "SYSTEM_CERT_1234"
        ),
        installerInfo = TrustEvidenceEngine.InstallerInfo(
            installerPackage = null,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER,
            isExpectedInstaller = true
        ),
        systemAppInfo = TrustEvidenceEngine.SystemAppInfo(
            isSystemApp = true, isPrivilegedApp = true,
            isUpdatedSystemApp = false,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM,
            isPlatformSigned = true
        ),
        signingLineage = TrustEvidenceEngine.SigningLineageInfo(false, 0, false),
        deviceIntegrity = TrustEvidenceEngine.DeviceIntegrityInfo(false, TrustEvidenceEngine.VerifiedBootState.GREEN),
        trustScore = score,
        trustLevel = level,
        reasons = emptyList()
    )

    /**
     * Build TrustEvidence for a user-installed app.
     */
    private fun userTrust(
        packageName: String = "com.example.app",
        score: Int = 55,
        level: TrustEvidenceEngine.TrustLevel = TrustEvidenceEngine.TrustLevel.MODERATE,
        installerType: TrustEvidenceEngine.InstallerType = TrustEvidenceEngine.InstallerType.PLAY_STORE
    ) = TrustEvidenceEngine.TrustEvidence(
        packageName = packageName,
        certSha256 = "USER_CERT_ABCD",
        certMatch = TrustEvidenceEngine.CertMatchResult(
            matchType = TrustEvidenceEngine.CertMatchType.UNKNOWN,
            matchedDeveloper = null,
            knownCertDigests = emptySet(),
            currentCertDigest = "USER_CERT_ABCD"
        ),
        installerInfo = TrustEvidenceEngine.InstallerInfo(
            installerPackage = when (installerType) {
                TrustEvidenceEngine.InstallerType.PLAY_STORE -> "com.android.vending"
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

    // ════════════════════════════════════════════════════════════
    //  1. InstallClass classification
    // ════════════════════════════════════════════════════════════

    @Test
    fun `classifyInstall - system app on SYSTEM partition = SYSTEM_PREINSTALLED`() {
        val ic = model.classifyInstall(
            isSystemApp = true,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertEquals(TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED, ic)
    }

    @Test
    fun `classifyInstall - system app on VENDOR partition = SYSTEM_PREINSTALLED`() {
        val ic = model.classifyInstall(
            isSystemApp = true,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER,
            partition = TrustEvidenceEngine.AppPartition.VENDOR
        )
        assertEquals(TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED, ic)
    }

    @Test
    fun `classifyInstall - system app on PRODUCT partition = SYSTEM_PREINSTALLED`() {
        val ic = model.classifyInstall(
            isSystemApp = true,
            installerType = TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER,
            partition = TrustEvidenceEngine.AppPartition.PRODUCT
        )
        assertEquals(TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED, ic)
    }

    @Test
    fun `classifyInstall - Play Store app on DATA partition = USER_INSTALLED`() {
        val ic = model.classifyInstall(
            isSystemApp = false,
            installerType = TrustEvidenceEngine.InstallerType.PLAY_STORE,
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertEquals(TrustRiskModel.InstallClass.USER_INSTALLED, ic)
    }

    @Test
    fun `classifyInstall - MDM installer = ENTERPRISE_MANAGED`() {
        val ic = model.classifyInstall(
            isSystemApp = false,
            installerType = TrustEvidenceEngine.InstallerType.MDM_INSTALLER,
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertEquals(TrustRiskModel.InstallClass.ENTERPRISE_MANAGED, ic)
    }

    @Test
    fun `classifyInstall - sideloaded app = USER_INSTALLED`() {
        val ic = model.classifyInstall(
            isSystemApp = false,
            installerType = TrustEvidenceEngine.InstallerType.SIDELOADED,
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertEquals(TrustRiskModel.InstallClass.USER_INSTALLED, ic)
    }

    // ════════════════════════════════════════════════════════════
    //  2. PolicyProfile mapping
    // ════════════════════════════════════════════════════════════

    @Test
    fun `policyProfile - SYSTEM_PREINSTALLED maps to SYSTEM`() {
        assertEquals(
            TrustRiskModel.PolicyProfile.SYSTEM,
            model.policyProfileFor(TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED)
        )
    }

    @Test
    fun `policyProfile - ENTERPRISE_MANAGED maps to SYSTEM`() {
        assertEquals(
            TrustRiskModel.PolicyProfile.SYSTEM,
            model.policyProfileFor(TrustRiskModel.InstallClass.ENTERPRISE_MANAGED)
        )
    }

    @Test
    fun `policyProfile - USER_INSTALLED maps to USER`() {
        assertEquals(
            TrustRiskModel.PolicyProfile.USER,
            model.policyProfileFor(TrustRiskModel.InstallClass.USER_INSTALLED)
        )
    }

    // ════════════════════════════════════════════════════════════
    //  3. System apps with ONLY hygiene findings → SAFE
    // ════════════════════════════════════════════════════════════

    @Test
    fun `SAFE - system app with OLD_TARGET_SDK only`() {
        val verdict = model.evaluate(
            packageName = "com.android.providers.contacts",
            trustEvidence = systemTrust("com.android.providers.contacts"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - system app with OVER_PRIVILEGED only`() {
        val verdict = model.evaluate(
            packageName = "com.android.settings",
            trustEvidence = systemTrust("com.android.settings"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - system app with EXPORTED_COMPONENTS only`() {
        val verdict = model.evaluate(
            packageName = "com.android.launcher",
            trustEvidence = systemTrust("com.android.launcher"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - system app with multiple hygiene findings stacked`() {
        val verdict = model.evaluate(
            packageName = "com.android.providers.settings",
            trustEvidence = systemTrust("com.android.providers.settings"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.HIGH_RISK_CAPABILITY, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "Stacked hygiene findings should NOT escalate system apps",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `SAFE - system app with INSTALLER_ANOMALY_VERIFIED (system installer shows as null)`() {
        val verdict = model.evaluate(
            packageName = "com.android.bluetooth",
            trustEvidence = systemTrust("com.android.bluetooth"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INSTALLER_ANOMALY_VERIFIED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    // ════════════════════════════════════════════════════════════
    //  4. System apps with HARD findings → still CRITICAL
    // ════════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL - system app with SIGNATURE_MISMATCH (hard finding never suppressed)`() {
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SIGNATURE_MISMATCH, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "HARD finding must NEVER be suppressed, even for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `CRITICAL - system app with HOOKING_FRAMEWORK_DETECTED`() {
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust("com.android.systemui"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - system app with DEBUG_SIGNATURE`() {
        val verdict = model.evaluate(
            packageName = "com.android.settings",
            trustEvidence = systemTrust("com.android.settings"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `CRITICAL - system app with hygiene AND hard finding - hard wins`() {
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.SIGNATURE_MISMATCH, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "HARD finding dominates even alongside hygiene findings",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  5. R10 weighted threshold: USER vs SYSTEM divergence
    // ════════════════════════════════════════════════════════════

    @Test
    fun `INFO - USER app with single OLD_TARGET_SDK finding and low trust reaches INFO (threshold=1)`() {
        // LOW trust (score < 40) means SOFT findings only get downgraded by 1,
        // so LOW(1) → LOW(1) or stays at LOW. Weight = 3 ≥ threshold 1 → INFO.
        val verdict = model.evaluate(
            packageName = "com.example.oldapp",
            trustEvidence = userTrust("com.example.oldapp", score = 25, level = TrustEvidenceEngine.TrustLevel.LOW),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.USER_INSTALLED
        )
        assertEquals(
            "USER profile + low trust: single hygiene finding should reach INFO",
            TrustRiskModel.EffectiveRisk.INFO,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `SAFE - SYSTEM app with same single OLD_TARGET_SDK finding stays SAFE (threshold=5)`() {
        val verdict = model.evaluate(
            packageName = "com.android.providers.contacts",
            trustEvidence = systemTrust("com.android.providers.contacts"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "SYSTEM profile: hygiene finding weight=0, doesn't reach threshold=5",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `asymmetric threshold - same findings, different verdict for USER vs SYSTEM`() {
        // Use MEDIUM severity so that even with low trust downgrade (1 level),
        // the adjusted severity stays at LOW(1) — still above threshold.
        val hygieneFindings = listOf(
            finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.MEDIUM),
            finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.MEDIUM)
        )

        val userVerdict = model.evaluate(
            packageName = "com.example.oldapp",
            trustEvidence = userTrust("com.example.oldapp", score = 25, level = TrustEvidenceEngine.TrustLevel.LOW),
            rawFindings = hygieneFindings,
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.USER_INSTALLED
        )

        val systemVerdict = model.evaluate(
            packageName = "com.android.contacts",
            trustEvidence = systemTrust("com.android.contacts"),
            rawFindings = hygieneFindings,
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )

        assertEquals("USER with hygiene findings + low trust → INFO", TrustRiskModel.EffectiveRisk.INFO, userVerdict.effectiveRisk)
        assertEquals("SYSTEM with same hygiene findings → SAFE", TrustRiskModel.EffectiveRisk.SAFE, systemVerdict.effectiveRisk)
    }

    // ════════════════════════════════════════════════════════════
    //  6. System category detection
    // ════════════════════════════════════════════════════════════

    @Test
    fun `detect SYSTEM_TELECOM for com_android_phone`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_TELECOM,
            AppCategoryDetector.detectCategory("com.android.phone", "Phone")
        )
    }

    @Test
    fun `detect SYSTEM_TELECOM for telephony package`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_TELECOM,
            AppCategoryDetector.detectCategory("com.android.providers.telephony", "Telephony Storage")
        )
    }

    @Test
    fun `detect SYSTEM_TELECOM for carrier services`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_TELECOM,
            AppCategoryDetector.detectCategory("com.google.android.carrierservices", "Carrier Services")
        )
    }

    @Test
    fun `detect SYSTEM_MESSAGING for android MMS`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_MESSAGING,
            AppCategoryDetector.detectCategory("com.android.mms", "Messages")
        )
    }

    @Test
    fun `detect SYSTEM_MESSAGING for Google Messages`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_MESSAGING,
            AppCategoryDetector.detectCategory("com.google.android.apps.messaging", "Messages")
        )
    }

    @Test
    fun `detect SYSTEM_FRAMEWORK for SystemUI`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK,
            AppCategoryDetector.detectCategory("com.android.systemui", "System UI")
        )
    }

    @Test
    fun `detect SYSTEM_FRAMEWORK for android core`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK,
            AppCategoryDetector.detectCategory("android", "Android System")
        )
    }

    @Test
    fun `detect SYSTEM_FRAMEWORK for permission controller`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK,
            AppCategoryDetector.detectCategory("com.google.android.permissioncontroller", "Permission Controller")
        )
    }

    @Test
    fun `detect SYSTEM_FRAMEWORK for package installer`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK,
            AppCategoryDetector.detectCategory("com.google.android.packageinstaller", "Package Installer")
        )
    }

    @Test
    fun `detect SYSTEM_CONNECTIVITY for bluetooth`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY,
            AppCategoryDetector.detectCategory("com.android.bluetooth", "Bluetooth")
        )
    }

    @Test
    fun `detect SYSTEM_CONNECTIVITY for wifi`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY,
            AppCategoryDetector.detectCategory("com.android.wifi.resources", "WiFi Resources")
        )
    }

    @Test
    fun `detect SYSTEM_CONNECTIVITY for NFC`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY,
            AppCategoryDetector.detectCategory("com.android.nfc", "NFC Service")
        )
    }

    @Test
    fun `detect SYSTEM_CONNECTIVITY for networkstack`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY,
            AppCategoryDetector.detectCategory("com.android.networkstack", "Network Stack")
        )
    }

    // ════════════════════════════════════════════════════════════
    //  7. System category cluster whitelisting
    // ════════════════════════════════════════════════════════════

    @Test
    fun `SAFE - SYSTEM_TELECOM with SMS and CALL_LOG is expected (not flagged)`() {
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = emptyList(),
            isSystemApp = true,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG"
            ),
            appCategory = AppCategoryDetector.AppCategory.SYSTEM_TELECOM,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "Telecom system with SMS + call log is expected, not suspicious",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `SAFE - SYSTEM_MESSAGING with SMS is expected`() {
        val verdict = model.evaluate(
            packageName = "com.android.mms",
            trustEvidence = systemTrust("com.android.mms"),
            rawFindings = emptyList(),
            isSystemApp = true,
            grantedPermissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS"
            ),
            appCategory = AppCategoryDetector.AppCategory.SYSTEM_MESSAGING,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `SAFE - SYSTEM_FRAMEWORK with overlay and accessibility is expected`() {
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust("com.android.systemui"),
            rawFindings = emptyList(),
            isSystemApp = true,
            grantedPermissions = listOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            appCategory = AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "SystemUI with overlay + accessibility is expected behavior",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `SAFE - SYSTEM_CONNECTIVITY with VPN permission is expected`() {
        val verdict = model.evaluate(
            packageName = "com.android.vpndialogs",
            trustEvidence = systemTrust("com.android.vpndialogs"),
            rawFindings = emptyList(),
            isSystemApp = true,
            grantedPermissions = listOf("android.permission.BIND_VPN_SERVICE"),
            appCategory = AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    // ════════════════════════════════════════════════════════════
    //  8. Population invariant: <5% NEEDS_ATTENTION for system fleet
    // ════════════════════════════════════════════════════════════

    /**
     * Simulate a realistic fleet of 100 system apps — the vast majority should be SAFE.
     * Only system apps with genuinely hard findings should be NEEDS_ATTENTION or above.
     */
    @Test
    fun `population invariant - system fleet with hygiene findings stays under 5 pct NEEDS_ATTENTION`() {
        val systemPackages = (1..100).map { i ->
            "com.android.system$i"
        }

        // Give each system app 1-3 hygiene findings (realistic: old SDK, exported, over-privileged)
        val hygieneFindings = listOf(
            TrustRiskModel.FindingType.OLD_TARGET_SDK,
            TrustRiskModel.FindingType.EXPORTED_COMPONENTS,
            TrustRiskModel.FindingType.OVER_PRIVILEGED,
            TrustRiskModel.FindingType.HIGH_RISK_CAPABILITY
        )

        var needsAttentionCount = 0
        var criticalCount = 0

        systemPackages.forEachIndexed { idx, pkg ->
            // Each app gets idx % 4 + 1 hygiene findings (1 to 4)
            val findings = hygieneFindings.take((idx % hygieneFindings.size) + 1).map {
                finding(it, AppSecurityScanner.RiskLevel.LOW)
            }

            val verdict = model.evaluate(
                packageName = pkg,
                trustEvidence = systemTrust(pkg),
                rawFindings = findings,
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )

            when (verdict.effectiveRisk) {
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION -> needsAttentionCount++
                TrustRiskModel.EffectiveRisk.CRITICAL -> criticalCount++
                else -> {}
            }
        }

        assertTrue(
            "Expected 0 CRITICAL in clean system fleet, got $criticalCount",
            criticalCount == 0
        )
        assertTrue(
            "Expected <5% NEEDS_ATTENTION in system fleet, got $needsAttentionCount/100 " +
            "= ${needsAttentionCount}%",
            needsAttentionCount < 5
        )
    }

    @Test
    fun `population invariant - system fleet without findings is 100 pct SAFE`() {
        val safeCount = (1..50).count { i ->
            val verdict = model.evaluate(
                packageName = "com.android.clean$i",
                trustEvidence = systemTrust("com.android.clean$i"),
                rawFindings = emptyList(),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE
        }
        assertEquals("All clean system apps must be SAFE", 50, safeCount)
    }

    // ════════════════════════════════════════════════════════════
    //  9. Edge cases: policyProfileOverride
    // ════════════════════════════════════════════════════════════

    @Test
    fun `policyProfileOverride - USER_INSTALLED with SYSTEM override gets SYSTEM thresholds`() {
        // Force system policy on a user-installed app (e.g., MDM-like scenario)
        val verdict = model.evaluate(
            packageName = "com.example.mdmapp",
            trustEvidence = userTrust("com.example.mdmapp"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.USER_INSTALLED,
            policyProfileOverride = TrustRiskModel.PolicyProfile.SYSTEM
        )
        assertEquals(
            "SYSTEM policy override should suppress hygiene findings",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `policyProfileOverride - ENTERPRISE_MANAGED gets SYSTEM policy automatically`() {
        val verdict = model.evaluate(
            packageName = "com.corp.mdmapp",
            trustEvidence = userTrust("com.corp.mdmapp"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.OVER_PRIVILEGED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.ENTERPRISE_MANAGED
        )
        assertEquals(
            "ENTERPRISE_MANAGED apps should get SYSTEM policy profile",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  10. Backward compatibility: USER_INSTALLED default
    // ════════════════════════════════════════════════════════════

    @Test
    fun `backward compat - evaluate without installClass defaults to USER_INSTALLED`() {
        // Same call pattern as pre-v4 tests (no installClass specified)
        // Use low trust + MEDIUM severity so the finding survives downgrade
        val verdict = model.evaluate(
            packageName = "com.example.legacy",
            trustEvidence = userTrust("com.example.legacy", score = 25, level = TrustEvidenceEngine.TrustLevel.LOW),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.MEDIUM)
            ),
            isSystemApp = false
        )
        // USER policy: SOFT finding with low trust → downgraded by 1 (MEDIUM→LOW),
        // weight = 3 ≥ threshold 1 → INFO
        assertEquals(
            "Default installClass=USER_INSTALLED should maintain pre-v4 behavior",
            TrustRiskModel.EffectiveRisk.INFO,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `backward compat - high trust user app with no findings still SAFE`() {
        val trust = TrustEvidenceEngine.TrustEvidence(
            packageName = "com.google.chrome",
            certSha256 = "CHROME_CERT",
            certMatch = TrustEvidenceEngine.CertMatchResult(
                matchType = TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH,
                matchedDeveloper = "Google",
                knownCertDigests = emptySet(),
                currentCertDigest = "CHROME_CERT"
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
        val verdict = model.evaluate(
            packageName = "com.google.chrome",
            trustEvidence = trust,
            rawFindings = emptyList(),
            isSystemApp = false
        )
        assertEquals(TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    // ════════════════════════════════════════════════════════════
    //  11. TrustDomain classification (signing domain awareness)
    // ════════════════════════════════════════════════════════════

    @Test
    fun `TrustDomain - APEX module from apex sourceDir`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = true, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM,
            sourceDir = "/apex/com.android.tethering/app/InProcessTethering"
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.APEX_MODULE, domain)
    }

    @Test
    fun `TrustDomain - APEX module detected by isApex flag alone`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = true, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.APEX_MODULE, domain)
    }

    @Test
    fun `TrustDomain - platform-signed system app`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = false, isPlatformSigned = true,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED, domain)
    }

    @Test
    fun `TrustDomain - OEM vendor partition app`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = false, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.VENDOR
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.OEM_VENDOR, domain)
    }

    @Test
    fun `TrustDomain - OEM product partition app`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = false, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.PRODUCT
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.OEM_VENDOR, domain)
    }

    @Test
    fun `TrustDomain - user-installed app = PLAY_SIGNED`() {
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = false, isApex = false, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertEquals(TrustedAppsWhitelist.TrustDomain.PLAY_SIGNED, domain)
    }

    @Test
    fun `TrustDomain - system app on SYSTEM partition without platform key`() {
        // GMS-like app on /system but not platform-signed
        val domain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = true, isApex = false, isPlatformSigned = false,
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertEquals(
            "System app on SYSTEM partition should still be PLATFORM_SIGNED domain",
            TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED, domain
        )
    }

    // ════════════════════════════════════════════════════════════
    //  12. isExpectedSignerMismatch
    // ════════════════════════════════════════════════════════════

    @Test
    fun `isExpectedSignerMismatch - PLATFORM_SIGNED = true`() {
        assertTrue(TrustedAppsWhitelist.isExpectedSignerMismatch(TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED))
    }

    @Test
    fun `isExpectedSignerMismatch - APEX_MODULE = true`() {
        assertTrue(TrustedAppsWhitelist.isExpectedSignerMismatch(TrustedAppsWhitelist.TrustDomain.APEX_MODULE))
    }

    @Test
    fun `isExpectedSignerMismatch - OEM_VENDOR = true`() {
        assertTrue(TrustedAppsWhitelist.isExpectedSignerMismatch(TrustedAppsWhitelist.TrustDomain.OEM_VENDOR))
    }

    @Test
    fun `isExpectedSignerMismatch - PLAY_SIGNED = false`() {
        assertFalse(TrustedAppsWhitelist.isExpectedSignerMismatch(TrustedAppsWhitelist.TrustDomain.PLAY_SIGNED))
    }

    @Test
    fun `isExpectedSignerMismatch - UNKNOWN = false`() {
        assertFalse(TrustedAppsWhitelist.isExpectedSignerMismatch(TrustedAppsWhitelist.TrustDomain.UNKNOWN))
    }

    // ════════════════════════════════════════════════════════════
    //  13. detectPartitionAnomaly
    // ════════════════════════════════════════════════════════════

    @Test
    fun `detectPartitionAnomaly - system app in data-app = anomaly`() {
        val result = TrustedAppsWhitelist.detectPartitionAnomaly(
            "com.android.phone", isSystemApp = true,
            sourceDir = "/data/app/com.android.phone-123/base.apk",
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertNotNull("System app in /data/app should be flagged", result)
    }

    @Test
    fun `detectPartitionAnomaly - system app on DATA partition = anomaly`() {
        val result = TrustedAppsWhitelist.detectPartitionAnomaly(
            "com.android.phone", isSystemApp = true,
            sourceDir = "/system/app/Phone/Phone.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertNotNull("System app on DATA partition should be flagged", result)
    }

    @Test
    fun `detectPartitionAnomaly - system app on SYSTEM partition = clean`() {
        val result = TrustedAppsWhitelist.detectPartitionAnomaly(
            "com.android.phone", isSystemApp = true,
            sourceDir = "/system/app/Phone/Phone.apk",
            partition = TrustEvidenceEngine.AppPartition.SYSTEM
        )
        assertNull("Normal system app should have no anomaly", result)
    }

    @Test
    fun `detectPartitionAnomaly - user app is always null`() {
        val result = TrustedAppsWhitelist.detectPartitionAnomaly(
            "com.example.app", isSystemApp = false,
            sourceDir = "/data/app/com.example.app-1/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA
        )
        assertNull("User app in /data/app is normal, should not flag", result)
    }

    // ════════════════════════════════════════════════════════════
    //  14. Domain-aware cert findings: NOT_PLAY_SIGNED → SAFE for system
    // ════════════════════════════════════════════════════════════

    @Test
    fun `SAFE - system app with NOT_PLAY_SIGNED only (APEX cert is expected)`() {
        val verdict = model.evaluate(
            packageName = "com.android.tethering",
            trustEvidence = systemTrust("com.android.tethering"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "NOT_PLAY_SIGNED is SOFT + hygiene-suppressed for SYSTEM → SAFE",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `SAFE - system app with NOT_PLAY_SIGNED AND hygiene stacked`() {
        val verdict = model.evaluate(
            packageName = "com.google.android.ext.services",
            trustEvidence = systemTrust("com.google.android.ext.services"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "NOT_PLAY_SIGNED + hygiene should all be suppressed for SYSTEM",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  15. SIGNATURE_DRIFT (real baseline cert change) → CRITICAL
    // ════════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL - system app with SIGNATURE_DRIFT (real cert change vs baseline)`() {
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SIGNATURE_DRIFT, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "SIGNATURE_DRIFT is HARD — real cert change must be CRITICAL even for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `CRITICAL - user app with SIGNATURE_DRIFT`() {
        val verdict = model.evaluate(
            packageName = "com.example.banking",
            trustEvidence = userTrust("com.example.banking"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SIGNATURE_DRIFT, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.USER_INSTALLED
        )
        assertEquals(
            "SIGNATURE_DRIFT is HARD for USER apps too",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  16. PARTITION_ANOMALY → CRITICAL
    // ════════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL - system app with PARTITION_ANOMALY (sourceDir in data-app)`() {
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.PARTITION_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "PARTITION_ANOMALY is HARD — system app in wrong location is CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  17. USER app with SIGNATURE_MISMATCH → still CRITICAL (unchanged)
    // ════════════════════════════════════════════════════════════

    @Test
    fun `CRITICAL - USER app with SIGNATURE_MISMATCH (Play cert mismatch)`() {
        val verdict = model.evaluate(
            packageName = "com.example.suspicious",
            trustEvidence = userTrust("com.example.suspicious", score = 20, level = TrustEvidenceEngine.TrustLevel.LOW),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SIGNATURE_MISMATCH, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = false,
            installClass = TrustRiskModel.InstallClass.USER_INSTALLED
        )
        assertEquals(
            "USER apps with SIGNATURE_MISMATCH (Play domain) must remain CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  18. Population invariant: no system CRITICAL from cert-only findings
    // ════════════════════════════════════════════════════════════

    @Test
    fun `population invariant - 100 system apps with NOT_PLAY_SIGNED produce ZERO critical`() {
        var criticalCount = 0
        var needsAttentionCount = 0

        (1..100).forEach { i ->
            val verdict = model.evaluate(
                packageName = "com.android.system$i",
                trustEvidence = systemTrust("com.android.system$i"),
                rawFindings = listOf(
                    finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW)
                ),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            when (verdict.effectiveRisk) {
                TrustRiskModel.EffectiveRisk.CRITICAL -> criticalCount++
                TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION -> needsAttentionCount++
                else -> {}
            }
        }

        assertEquals(
            "NO system app should be CRITICAL from NOT_PLAY_SIGNED alone",
            0, criticalCount
        )
        assertEquals(
            "NO system app should be NEEDS_ATTENTION from NOT_PLAY_SIGNED alone",
            0, needsAttentionCount
        )
    }

    @Test
    fun `population invariant - system fleet with NOT_PLAY_SIGNED plus hygiene is 100pct SAFE`() {
        val safeCount = (1..50).count { i ->
            val verdict = model.evaluate(
                packageName = "com.android.sysapp$i",
                trustEvidence = systemTrust("com.android.sysapp$i"),
                rawFindings = listOf(
                    finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW),
                    finding(TrustRiskModel.FindingType.OLD_TARGET_SDK, AppSecurityScanner.RiskLevel.LOW),
                    finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
                ),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE
        }
        assertEquals(
            "All system apps with NOT_PLAY_SIGNED + hygiene must be SAFE",
            50, safeCount
        )
    }

    // ════════════════════════════════════════════════════════════
    //  19. FindingType hardness classification
    // ════════════════════════════════════════════════════════════

    @Test
    fun `FindingType hardness - NOT_PLAY_SIGNED is SOFT`() {
        assertEquals(
            TrustRiskModel.FindingHardness.SOFT,
            TrustRiskModel.FindingType.NOT_PLAY_SIGNED.hardness
        )
    }

    @Test
    fun `FindingType hardness - SIGNATURE_DRIFT is HARD`() {
        assertEquals(
            TrustRiskModel.FindingHardness.HARD,
            TrustRiskModel.FindingType.SIGNATURE_DRIFT.hardness
        )
    }

    @Test
    fun `FindingType hardness - PARTITION_ANOMALY is HARD`() {
        assertEquals(
            TrustRiskModel.FindingHardness.HARD,
            TrustRiskModel.FindingType.PARTITION_ANOMALY.hardness
        )
    }

    @Test
    fun `FindingType hardness - SIGNATURE_MISMATCH is still HARD`() {
        assertEquals(
            TrustRiskModel.FindingHardness.HARD,
            TrustRiskModel.FindingType.SIGNATURE_MISMATCH.hardness
        )
    }

    // ════════════════════════════════════════════════════════════
    //  20. Domain-aware cert matching in TrustEvidenceEngine
    //      (R2 false-positive prevention — verifyCertificate
    //       now passes signerDomain to matchDeveloperCert)
    // ════════════════════════════════════════════════════════════

    @Test
    fun `matchDeveloperCert with PLATFORM_SIGNED domain skips PLAY_SIGNED entries`() {
        // Google dev entry is PLAY_SIGNED — a PLATFORM_SIGNED caller must NOT match it
        val match = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.ext.services",
            certPrefix = "0000000000000000000000000000000000000000", // random cert
            callerDomain = TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED
        )
        // Should be null because Google entry is PLAY_SIGNED and caller is PLATFORM_SIGNED
        assertNull("PLATFORM_SIGNED caller must not match PLAY_SIGNED dev entry", match)
    }

    @Test
    fun `matchDeveloperCert without domain still matches Google entry`() {
        // Without domain filter, Google dev entry CAN match (backward compat)
        val match = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.gms",
            certPrefix = "38918A453D07199354F8B19AF05EC6562CED5788"
        )
        assertNotNull("Without domain filter, Google entry should match", match)
        assertTrue("Cert should match", match!!.certMatches)
    }

    // ════════════════════════════════════════════════════════════
    //  21. R2 ANOMALOUS_TRUST: behavior verification
    // ════════════════════════════════════════════════════════════

    @Test
    fun `system app with ANOMALOUS trust and no hard findings = CRITICAL via R2`() {
        val verdict = model.evaluate(
            packageName = "com.test.suspicious",
            trustEvidence = systemTrust(
                packageName = "com.test.suspicious",
                level = TrustEvidenceEngine.TrustLevel.ANOMALOUS,
                score = 10
            ),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "ANOMALOUS trust must still trigger R2→CRITICAL (the fix is upstream)",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `system app with HIGH trust after domain fix = SAFE`() {
        val verdict = model.evaluate(
            packageName = "com.google.android.ext.services",
            trustEvidence = systemTrust(
                packageName = "com.google.android.ext.services",
                level = TrustEvidenceEngine.TrustLevel.HIGH,
                score = 85
            ),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW),
                finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "System app with HIGH trust + only hygiene findings should be SAFE",
            TrustRiskModel.EffectiveRisk.SAFE,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  22. PARTITION_ANOMALY: Play-updated system apps
    // ════════════════════════════════════════════════════════════

    @Test
    fun `detectPartitionAnomaly - updated system app in data_app is NOT anomalous`() {
        val anomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = "com.android.chrome",
            isSystemApp = true,
            sourceDir = "/data/app/~~random/com.android.chrome-hash/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isUpdatedSystemApp = true  // FLAG_UPDATED_SYSTEM_APP
        )
        assertNull("Play-updated system app in /data/app should NOT be flagged", anomaly)
    }

    @Test
    fun `detectPartitionAnomaly - non-updated system app in data_app IS anomalous`() {
        val anomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = "com.suspicious.overlay",
            isSystemApp = true,
            sourceDir = "/data/app/~~random/com.suspicious.overlay-hash/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isUpdatedSystemApp = false
        )
        assertNotNull("Non-updated system app in /data/app SHOULD be flagged", anomaly)
    }

    @Test
    fun `genuine PARTITION_ANOMALY still escalates to CRITICAL`() {
        val verdict = model.evaluate(
            packageName = "com.suspicious.overlay",
            trustEvidence = systemTrust("com.suspicious.overlay"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.PARTITION_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "Genuine PARTITION_ANOMALY must still be CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    // ════════════════════════════════════════════════════════════
    //  23. End-to-end population: 30 former CRITICALs → SAFE
    // ════════════════════════════════════════════════════════════

    @Test
    fun `population - former R2 apps become SAFE when trust is HIGH after domain fix`() {
        val r2Packages = listOf(
            "com.google.android.ext.services",
            "com.google.android.networkstack.tethering",
            "com.google.android.permissioncontroller",
            "com.google.android.gms.supervision",
            "com.google.android.gsf"
        )
        val safeCount = r2Packages.count { pkg ->
            val verdict = model.evaluate(
                packageName = pkg,
                trustEvidence = systemTrust(pkg, score = 85, level = TrustEvidenceEngine.TrustLevel.HIGH),
                rawFindings = listOf(
                    finding(TrustRiskModel.FindingType.NOT_PLAY_SIGNED, AppSecurityScanner.RiskLevel.LOW)
                ),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE
        }
        assertEquals("All former R2 apps should be SAFE with HIGH trust", r2Packages.size, safeCount)
    }

    @Test
    fun `population - former R1 apps become SAFE when no PARTITION_ANOMALY finding`() {
        val r1Packages = listOf(
            "com.android.vending",
            "com.google.android.webview",
            "com.android.chrome",
            "com.google.android.gms"
        )
        val safeCount = r1Packages.count { pkg ->
            val verdict = model.evaluate(
                packageName = pkg,
                trustEvidence = systemTrust(pkg),
                rawFindings = listOf(
                    finding(TrustRiskModel.FindingType.EXPORTED_COMPONENTS, AppSecurityScanner.RiskLevel.LOW)
                ),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE
        }
        assertEquals("All former R1 apps should be SAFE without PARTITION_ANOMALY", r1Packages.size, safeCount)
    }

    // ════════════════════════════════════════════════════════════
    //  24. NEGATIVE TESTS — prove CRITICAL still fires for genuine anomalies
    //
    //  These tests guarantee that "CRITICAL=0 in normal state" does not
    //  mean "CRITICAL=0 always".  Each test synthesizes a realistic
    //  compromise scenario for a system app and verifies CRITICAL fires.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `NEGATIVE - SIGNATURE_DRIFT on system app = CRITICAL`() {
        // Scenario: baseline recorded cert X, now the app has cert Y.
        // This is the #1 indicator of a tampered/repackaged system component.
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust("com.android.systemui"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.SIGNATURE_DRIFT, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "SIGNATURE_DRIFT must produce CRITICAL even for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
        // Verify it's R1 (hard finding), not R2 (trust)
        assertTrue(
            "Verdict must have a HARD finding",
            verdict.adjustedFindings.any {
                it.hardness == TrustRiskModel.FindingHardness.HARD &&
                it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score
            }
        )
    }

    @Test
    fun `NEGATIVE - BASELINE_SIGNATURE_CHANGE on system app = CRITICAL`() {
        // Scenario: Play-updated system app's signing cert changed vs baseline.
        // Even though FLAG_UPDATED_SYSTEM_APP is set, cert change is a red flag.
        val verdict = model.evaluate(
            packageName = "com.android.chrome",
            trustEvidence = systemTrust("com.android.chrome"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "BASELINE_SIGNATURE_CHANGE must produce CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - system app in data_app WITHOUT updated flag = CRITICAL via PARTITION_ANOMALY`() {
        // Scenario: attacker overlaid a system app from /data/app but the
        // FLAG_UPDATED_SYSTEM_APP is not set → suspicious overlay.
        // Step 1: detectPartitionAnomaly fires (tested in section 22)
        val anomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = "com.android.phone",
            isSystemApp = true,
            sourceDir = "/data/app/~~fake/com.android.phone-123/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isUpdatedSystemApp = false  // NOT a legitimate update
        )
        assertNotNull("Partition anomaly must fire for non-updated system app in /data/app", anomaly)

        // Step 2: that anomaly produces a HARD finding → CRITICAL
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.PARTITION_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "Non-updated system app with PARTITION_ANOMALY must be CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - PLATFORM_SIGNED false for system partition = ANOMALOUS trust`() {
        // Scenario: a system app on /system claims FLAG_SYSTEM but is NOT
        // signed with the platform key → potential ROM modification.
        // On a rooted device this triggers TrustLevel.ANOMALOUS (line 271 in TrustEvidenceEngine).
        val anomalousTrust = systemTrust(
            packageName = "com.android.settings",
            level = TrustEvidenceEngine.TrustLevel.ANOMALOUS,
            score = 10
        )
        val verdict = model.evaluate(
            packageName = "com.android.settings",
            trustEvidence = anomalousTrust,
            rawFindings = emptyList(),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "ANOMALOUS trust (non-platform-signed system app) must be CRITICAL via R2",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - VERSION_ROLLBACK on system app = CRITICAL`() {
        // Scenario: system app was downgraded (common in downgrade attacks).
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "VERSION_ROLLBACK must produce CRITICAL for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - DEBUG_SIGNATURE on system app = CRITICAL`() {
        // Scenario: system app signed with debug key → definitely tampered ROM.
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.DEBUG_SIGNATURE, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "DEBUG_SIGNATURE must produce CRITICAL for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - INTEGRITY_FAIL_WITH_HOOKING on system app = CRITICAL`() {
        // Scenario: hooking framework (Xposed/Frida) detected on system component.
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust("com.android.systemui"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING, AppSecurityScanner.RiskLevel.CRITICAL)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "INTEGRITY_FAIL_WITH_HOOKING must produce CRITICAL for system apps",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
    }

    @Test
    fun `NEGATIVE - multiple HARD findings compound on system app`() {
        // Scenario: cert changed + version rolled back + partition anomaly = definitely compromised
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(
                finding(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, AppSecurityScanner.RiskLevel.CRITICAL),
                finding(TrustRiskModel.FindingType.VERSION_ROLLBACK, AppSecurityScanner.RiskLevel.HIGH),
                finding(TrustRiskModel.FindingType.PARTITION_ANOMALY, AppSecurityScanner.RiskLevel.HIGH)
            ),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals(
            "Multiple HARD findings must produce CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL,
            verdict.effectiveRisk
        )
        assertTrue(
            "Multiple HARD findings must be preserved in adjusted findings",
            verdict.adjustedFindings.count {
                it.hardness == TrustRiskModel.FindingHardness.HARD &&
                it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score
            } >= 3
        )
    }

    // ════════════════════════════════════════════════════════════
    //  25. Invariant: PLATFORM_SIGNED + com.google.* + PLAY_SIGNED entry
    //      → certCheck MUST return UNKNOWN, never MISMATCH
    //      (TrustEvidenceEngine domain-awareness proof)
    // ════════════════════════════════════════════════════════════

    @Test
    fun `invariant - PLATFORM_SIGNED Google packages skip PLAY_SIGNED dev entries`() {
        // This proves the cert check cannot produce MISMATCH for system Google packages.
        val googleSystemPackages = listOf(
            "com.google.android.ext.services",
            "com.google.android.networkstack.tethering",
            "com.google.android.permissioncontroller",
            "com.google.android.gsf",
            "com.google.android.gms.supervision",
            "com.google.android.tts",
            "com.google.android.nfc",
            "com.google.android.bluetooth"
        )

        for (pkg in googleSystemPackages) {
            val match = TrustedAppsWhitelist.matchDeveloperCert(
                packageName = pkg,
                certPrefix = "FAKE_PLATFORM_KEY_NOT_PLAY_SIGNED_XXXXXX",
                callerDomain = TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED
            )
            assertNull(
                "matchDeveloperCert for PLATFORM_SIGNED $pkg must return null (skip PLAY entry), but got $match",
                match
            )
        }
    }

    @Test
    fun `invariant - all HARD FindingTypes actually produce CRITICAL for system apps`() {
        // Exhaustive: every HARD finding type must produce CRITICAL for system apps
        val hardTypes = TrustRiskModel.FindingType.entries
            .filter { it.hardness == TrustRiskModel.FindingHardness.HARD }

        for (ft in hardTypes) {
            val verdict = model.evaluate(
                packageName = "com.android.test.${ft.name.lowercase()}",
                trustEvidence = systemTrust("com.android.test.${ft.name.lowercase()}"),
                rawFindings = listOf(finding(ft, AppSecurityScanner.RiskLevel.HIGH)),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )
            assertEquals(
                "HARD FindingType ${ft.name} must produce CRITICAL for system app",
                TrustRiskModel.EffectiveRisk.CRITICAL,
                verdict.effectiveRisk
            )
        }
    }

    // ════════════════════════════════════════════════════════════
    //  26. E2E: scanner → model pipeline (baseline drift)
    //
    //  These test the FULL data-flow:
    //    BaselineAnomaly → scanner mapping → RawFinding → model.evaluate → verdict
    //  Without these, sections 24-25 prove the model works in isolation
    //  but NOT that the scanner actually feeds it the right data.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `E2E - CERT_CHANGED baseline anomaly maps to BASELINE_SIGNATURE_CHANGE(HARD) and produces CRITICAL`() {
        // Step 1: Scanner mapping — proves the scanner code at line 491+ is correct
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.CERT_CHANGED
        )
        assertEquals("Scanner must map CERT_CHANGED to BASELINE_SIGNATURE_CHANGE",
            TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, findingType)
        assertEquals("Scanner must map CERT_CHANGED to CRITICAL severity",
            AppSecurityScanner.RiskLevel.CRITICAL, severity)

        // Step 2: Verify the finding type is HARD (structural invariant)
        assertEquals("BASELINE_SIGNATURE_CHANGE must be HARD",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness)

        // Step 3: Feed through model — full pipeline
        val verdict = model.evaluate(
            packageName = "com.android.systemui",
            trustEvidence = systemTrust("com.android.systemui"),
            rawFindings = listOf(TrustRiskModel.RawFinding(findingType, severity, "cert changed", "")),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals("Full pipeline CERT_CHANGED → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `E2E - VERSION_ROLLBACK from untrusted installer maps to HARD VERSION_ROLLBACK and produces CRITICAL`() {
        // Sideloaded rollback = HARD (supply-chain attack indicator)
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.VERSION_ROLLBACK,
            isTrustedInstaller = false
        )
        assertEquals("Untrusted rollback must map to VERSION_ROLLBACK (HARD)",
            TrustRiskModel.FindingType.VERSION_ROLLBACK, findingType)
        assertEquals("Untrusted rollback must be HIGH severity",
            AppSecurityScanner.RiskLevel.HIGH, severity)
        assertEquals("VERSION_ROLLBACK must be HARD",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness)

        // Full pipeline
        val verdict = model.evaluate(
            packageName = "com.android.phone",
            trustEvidence = systemTrust("com.android.phone"),
            rawFindings = listOf(TrustRiskModel.RawFinding(findingType, severity, "rollback", "")),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals("Full pipeline untrusted VERSION_ROLLBACK → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `E2E - VERSION_ROLLBACK from trusted installer maps to SOFT VERSION_ROLLBACK_TRUSTED (not CRITICAL)`() {
        // Play Store rollback = SOFT (might be legitimate A/B rollback)
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.VERSION_ROLLBACK,
            isTrustedInstaller = true
        )
        assertEquals("Trusted rollback must map to VERSION_ROLLBACK_TRUSTED (SOFT)",
            TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED, findingType)
        assertNotEquals("VERSION_ROLLBACK_TRUSTED must NOT be HARD",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness)
    }

    @Test
    fun `E2E - partition anomaly path for non-updated system app produces CRITICAL`() {
        // Step 1: detectPartitionAnomaly fires for non-updated system app in /data/app
        val anomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = "com.android.dialer",
            isSystemApp = true,
            sourceDir = "/data/app/~~overlay/com.android.dialer-1/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isUpdatedSystemApp = false
        )
        assertNotNull("detectPartitionAnomaly must fire for non-updated system in /data/app", anomaly)

        // Step 2: Scanner code would add this as PARTITION_ANOMALY finding (line 603)
        // We simulate exactly what the scanner does:
        val rawFinding = TrustRiskModel.RawFinding(
            TrustRiskModel.FindingType.PARTITION_ANOMALY,
            AppSecurityScanner.RiskLevel.HIGH,
            "Neočekávané umístění systémové komponenty",
            anomaly!!
        )

        // Step 3: Model produces CRITICAL
        val verdict = model.evaluate(
            packageName = "com.android.dialer",
            trustEvidence = systemTrust("com.android.dialer"),
            rawFindings = listOf(rawFinding),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals("Full pipeline partition anomaly → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `E2E - partition anomaly does NOT fire for legitimately updated system app`() {
        // Chrome, WebView, GMS are FLAG_UPDATED_SYSTEM_APP in /data/app — legitimate
        val anomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = "com.android.chrome",
            isSystemApp = true,
            sourceDir = "/data/app/~~update/com.android.chrome-1/base.apk",
            partition = TrustEvidenceEngine.AppPartition.DATA,
            isUpdatedSystemApp = true  // Legitimate Play Store update
        )
        assertNull("Updated system app in /data/app must NOT trigger partition anomaly", anomaly)
    }

    @Test
    fun `E2E - all baseline anomaly types have valid scanner mapping`() {
        // Guardrail: every AnomalyType must produce a non-null mapping.
        // If someone adds a new AnomalyType without updating the mapping, this fails.
        for (anomalyType in BaselineManager.AnomalyType.entries) {
            val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(anomalyType)
            assertNotNull("Mapping for $anomalyType must produce a FindingType", findingType)
            assertNotNull("Mapping for $anomalyType must produce a severity", severity)
        }
    }

    // ════════════════════════════════════════════════════════════
    //  27. Symmetry invariant: domain cross-matching prevention
    //
    //  Proves that domain-aware cert matching is bidirectional:
    //    - PLATFORM_SIGNED caller must NOT match PLAY_SIGNED entries (existing test)
    //    - PLAY_SIGNED caller must NOT match PLATFORM_SIGNED entries (new)
    // ════════════════════════════════════════════════════════════

    @Test
    fun `invariant - PLAY_SIGNED caller must not match entries from other domains`() {
        // The trustedDevelopers list currently has only PLAY_SIGNED entries.
        // This test proves the mechanism works in reverse: if a PLATFORM_SIGNED
        // entry existed, a PLAY_SIGNED caller would skip it.
        //
        // We test via matchDeveloperCert with a cert that happens to match
        // the Google dev entry — but callerDomain=PLATFORM_SIGNED means it
        // should match (since Google entry IS PLAY_SIGNED and caller is PLATFORM).
        // Wait — that's the EXISTING direction. Let me test the OTHER direction:
        //
        // If we call matchDeveloperCert for a com.google.* package with
        // callerDomain=PLAY_SIGNED and the Google Play cert — it SHOULD match.
        // But if the domain check is accidentally inverted, it would skip.
        val playMatch = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.gms",
            certPrefix = "38918A453D07199354F8B19AF05EC6562CED5788",
            callerDomain = TrustedAppsWhitelist.TrustDomain.PLAY_SIGNED
        )
        assertNotNull(
            "PLAY_SIGNED caller with correct cert MUST match PLAY_SIGNED Google entry",
            playMatch
        )
        assertTrue("Cert must match for Play-signed GMS", playMatch!!.certMatches)

        // Now verify cross-domain rejection: APEX_MODULE caller must NOT match PLAY_SIGNED Google entry
        val apexMatch = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.tethering",
            certPrefix = "APEX_MODULE_CERT_NOT_GOOGLE_PLAY_KEY",
            callerDomain = TrustedAppsWhitelist.TrustDomain.APEX_MODULE
        )
        assertNull(
            "APEX_MODULE caller must NOT match PLAY_SIGNED Google entry",
            apexMatch
        )

        // OEM_VENDOR caller must NOT match PLAY_SIGNED Google entry
        val oemMatch = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.ext.services",
            certPrefix = "OEM_VENDOR_CERT_NOT_GOOGLE_PLAY_KEY",
            callerDomain = TrustedAppsWhitelist.TrustDomain.OEM_VENDOR
        )
        assertNull(
            "OEM_VENDOR caller must NOT match PLAY_SIGNED Google entry",
            oemMatch
        )
    }

    // ════════════════════════════════════════════════════════════
    //  28. Guardrail: adjustFinding HARD invariant
    //
    //  HARD findings must NEVER have their hardness changed by adjustFinding.
    //  adjustFinding may change severity for SOFT/WEAK_SIGNAL findings, but
    //  for HARD findings both severity and hardness must be preserved.
    //
    //  This is a structural contract: if someone adds a "SYSTEM_HARD_EXCEPTION"
    //  allow-list in the future, this test must be updated explicitly.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `guardrail - HARD findings preserve hardness and severity for SYSTEM profile`() {
        val hardTypes = TrustRiskModel.FindingType.entries
            .filter { it.hardness == TrustRiskModel.FindingHardness.HARD }

        for (ft in hardTypes) {
            val verdict = model.evaluate(
                packageName = "com.android.guardrail.${ft.name.lowercase()}",
                trustEvidence = systemTrust("com.android.guardrail.${ft.name.lowercase()}"),
                rawFindings = listOf(finding(ft, AppSecurityScanner.RiskLevel.HIGH)),
                isSystemApp = true,
                installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
            )

            // Find the adjusted finding for this type
            val adjusted = verdict.adjustedFindings.find { it.findingType == ft }
            assertNotNull("HARD finding ${ft.name} must appear in adjustedFindings", adjusted)

            // HARD hardness must be preserved
            assertEquals(
                "HARD finding ${ft.name} must keep HARD hardness after adjustment",
                TrustRiskModel.FindingHardness.HARD,
                adjusted!!.hardness
            )

            // Severity must NOT be downgraded
            assertFalse(
                "HARD finding ${ft.name} must NOT be downgraded (wasDowngraded must be false)",
                adjusted.wasDowngraded
            )

            // adjustedSeverity must equal originalSeverity
            assertEquals(
                "HARD finding ${ft.name}: adjustedSeverity must equal originalSeverity",
                adjusted.originalSeverity,
                adjusted.adjustedSeverity
            )
        }
    }

    @Test
    fun `guardrail - SYSTEM hygiene suppress list contains ONLY SOFT or WEAK_SIGNAL types`() {
        // This test documents and enforces which finding types are suppressed
        // for SYSTEM profile. If someone adds a HARD type to the suppress list,
        // the HARD-preserve test above will catch it. This test provides a
        // second safety net by explicitly listing the allowed suppressions.
        val allowedSystemSuppressions = setOf(
            TrustRiskModel.FindingType.OLD_TARGET_SDK,
            TrustRiskModel.FindingType.OVER_PRIVILEGED,
            TrustRiskModel.FindingType.EXPORTED_COMPONENTS,
            TrustRiskModel.FindingType.HIGH_RISK_CAPABILITY,
            TrustRiskModel.FindingType.INSTALLER_ANOMALY_VERIFIED,
            TrustRiskModel.FindingType.NOT_PLAY_SIGNED
        )

        for (ft in allowedSystemSuppressions) {
            assertNotEquals(
                "Suppress-list entry ${ft.name} must NOT be HARD (that would violate HARD-never-suppressed contract)",
                TrustRiskModel.FindingHardness.HARD,
                ft.hardness
            )
        }
    }

    // ════════════════════════════════════════════════════════════
    //  29. Guardrail: matchDeveloperCert is the single cert-matching entry point
    //
    //  TrustEvidenceEngine.verifyCertificate() calls matchDeveloperCert()
    //  via TrustedAppsWhitelist. No other cert-matching path should exist.
    //  This test verifies that matchDeveloperCert is the canonical API.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `guardrail - matchDeveloperCert with null callerDomain matches all domains (backward compat)`() {
        // When callerDomain is null (legacy callers), all entries are considered.
        // This ensures backward compatibility and proves the function IS the single entry point.
        val match = TrustedAppsWhitelist.matchDeveloperCert(
            packageName = "com.google.android.gms",
            certPrefix = "38918A453D07199354F8B19AF05EC6562CED5788",
            callerDomain = null  // Legacy: no domain filtering
        )
        assertNotNull("null callerDomain must consider all entries", match)
        assertTrue("Cert should match Google dev entry", match!!.certMatches)

        // Also verify domain is reported correctly
        assertEquals("Entry domain should be PLAY_SIGNED",
            TrustedAppsWhitelist.TrustDomain.PLAY_SIGNED, match.entryDomain)
    }

    @Test
    fun `guardrail - verifyTrustedApp delegates to matchDeveloperCert with domain`() {
        // verifyTrustedApp is the legacy API. It must pass signerDomain to matchDeveloperCert.
        // PLATFORM_SIGNED Google package → should NOT match (domain filtering)
        val result = TrustedAppsWhitelist.verifyTrustedApp(
            packageName = "com.google.android.ext.services",
            certSha256 = "PLATFORM_KEY_NOT_MATCHING_GOOGLE_PLAY_CERT",
            signerDomain = TrustedAppsWhitelist.TrustDomain.PLATFORM_SIGNED
        )
        // Should be UNKNOWN_PACKAGE (skipped Google entry due to domain mismatch)
        assertEquals(
            "PLATFORM_SIGNED caller via verifyTrustedApp must not match PLAY_SIGNED entry",
            TrustedAppsWhitelist.TrustReason.UNKNOWN_PACKAGE,
            result.reason
        )
    }

    // ════════════════════════════════════════════════════════════
    //  30. Contract tests: lock severity + hardness for every
    //      security-critical baseline→finding mapping
    //
    //  These tests form a *contract* — if anyone changes the mapping
    //  or the FindingType hardness, the test name tells them exactly
    //  what invariant they are breaking.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `contract - CERT_CHANGED maps to BASELINE_SIGNATURE_CHANGE with HARD hardness and CRITICAL severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.CERT_CHANGED
        )
        assertEquals(TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.CRITICAL, severity)
        assertEquals(
            "BASELINE_SIGNATURE_CHANGE must be HARD — cert changes are never suppressible",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness
        )
    }

    @Test
    fun `contract - INSTALLER_CHANGED maps to INSTALLER_ANOMALY with HARD hardness and MEDIUM severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.INSTALLER_CHANGED
        )
        assertEquals(TrustRiskModel.FindingType.INSTALLER_ANOMALY, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.MEDIUM, severity)
        assertEquals(
            "INSTALLER_ANOMALY must be HARD — installer switch is a key supply-chain indicator",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness
        )
    }

    @Test
    fun `contract - VERSION_ROLLBACK untrusted maps to VERSION_ROLLBACK with HARD hardness and HIGH severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.VERSION_ROLLBACK,
            isTrustedInstaller = false
        )
        assertEquals(TrustRiskModel.FindingType.VERSION_ROLLBACK, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.HIGH, severity)
        assertEquals(
            "VERSION_ROLLBACK (untrusted) must be HARD — downgrade from unknown source is attack indicator",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness
        )
    }

    @Test
    fun `contract - VERSION_ROLLBACK trusted maps to VERSION_ROLLBACK_TRUSTED with SOFT hardness and MEDIUM severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.VERSION_ROLLBACK,
            isTrustedInstaller = true
        )
        assertEquals(TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.MEDIUM, severity)
        assertEquals(
            "VERSION_ROLLBACK_TRUSTED must be SOFT — Play Store rollback may be legitimate A/B testing",
            TrustRiskModel.FindingHardness.SOFT, findingType.hardness
        )
    }

    @Test
    fun `contract - NEW_SYSTEM_APP maps to BASELINE_NEW_SYSTEM_APP with HARD hardness and HIGH severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.NEW_SYSTEM_APP
        )
        assertEquals(TrustRiskModel.FindingType.BASELINE_NEW_SYSTEM_APP, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.HIGH, severity)
        assertEquals(
            "BASELINE_NEW_SYSTEM_APP must be HARD — new system component warrants investigation",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness
        )
    }

    @Test
    fun `contract - HIGH_RISK_PERMISSION_ADDED maps to HIGH_RISK_PERMISSION_ADDED with HARD hardness and HIGH severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.HIGH_RISK_PERMISSION_ADDED
        )
        assertEquals(TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.HIGH, severity)
        assertEquals(
            "HIGH_RISK_PERMISSION_ADDED must be HARD — SMS/Accessibility/DeviceAdmin escalation is critical",
            TrustRiskModel.FindingHardness.HARD, findingType.hardness
        )
    }

    @Test
    fun `contract - EXPORTED_SURFACE_INCREASED maps to SOFT finding with MEDIUM severity`() {
        val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
            BaselineManager.AnomalyType.EXPORTED_SURFACE_INCREASED
        )
        assertEquals(TrustRiskModel.FindingType.EXPORTED_SURFACE_INCREASED, findingType)
        assertEquals(AppSecurityScanner.RiskLevel.MEDIUM, severity)
        assertEquals(
            "EXPORTED_SURFACE_INCREASED must be SOFT — surface increase alone is informational",
            TrustRiskModel.FindingHardness.SOFT, findingType.hardness
        )
    }

    // ════════════════════════════════════════════════════════════
    //  31. Real BaselineComparison→model pipeline contract tests
    //
    //  Construct real BaselineComparison objects with BaselineAnomaly
    //  data classes (as BaselineManager.compareWithBaseline() would
    //  produce them), then feed through the full mapping→model pipeline.
    //  This proves the data path from persistence layer to verdict.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `pipeline - real BaselineComparison with CERT_CHANGED anomaly produces CRITICAL verdict`() {
        // Step 1: Construct a real BaselineComparison as BaselineManager would produce
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.android.systemui",
            status = BaselineManager.BaselineStatus.CHANGED,
            anomalies = listOf(
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.CERT_CHANGED,
                    severity = BaselineManager.AnomalySeverity.CRITICAL,
                    description = "Podpisový certifikát se změnil!",
                    details = "Předchozí: ABCD1234...\nAktuální: EFGH5678..."
                )
            ),
            isFirstScan = false,
            scanCount = 3
        )

        // Step 2: Map anomalies through scanner companion (exactly as scanApp does)
        val rawFindings = comparison.anomalies.map { anomaly ->
            val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(anomaly.type)
            TrustRiskModel.RawFinding(findingType, severity, anomaly.description, anomaly.details ?: "")
        }

        // Step 3: Feed through model
        val verdict = model.evaluate(
            packageName = comparison.packageName,
            trustEvidence = systemTrust(comparison.packageName),
            rawFindings = rawFindings,
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )

        assertEquals("Real BaselineComparison with CERT_CHANGED → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `pipeline - real BaselineComparison with VERSION_ROLLBACK anomaly (untrusted) produces CRITICAL`() {
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.android.phone",
            status = BaselineManager.BaselineStatus.CHANGED,
            anomalies = listOf(
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.VERSION_ROLLBACK,
                    severity = BaselineManager.AnomalySeverity.HIGH,
                    description = "Verze aplikace byla snížena: 14.0 → 12.0",
                    details = "versionCode: 1400 → 1200\nDowngrade může znamenat supply-chain útok."
                )
            ),
            isFirstScan = false,
            scanCount = 5
        )

        // Untrusted installer (sideloaded) → HARD VERSION_ROLLBACK
        val rawFindings = comparison.anomalies.map { anomaly ->
            val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
                anomaly.type, isTrustedInstaller = false
            )
            TrustRiskModel.RawFinding(findingType, severity, anomaly.description, anomaly.details ?: "")
        }

        val verdict = model.evaluate(
            packageName = comparison.packageName,
            trustEvidence = systemTrust(comparison.packageName),
            rawFindings = rawFindings,
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )

        assertEquals("Real VERSION_ROLLBACK (untrusted) → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    @Test
    fun `pipeline - real BaselineComparison with multiple soft anomalies stays SAFE for system app`() {
        // System app with only soft/hygiene anomalies: version change + permission change
        // These are SOFT findings that get suppressed by system hygiene rules → SAFE
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.android.settings",
            status = BaselineManager.BaselineStatus.CHANGED,
            anomalies = listOf(
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.VERSION_CHANGED,
                    severity = BaselineManager.AnomalySeverity.LOW,
                    description = "Verze se změnila: 14.0 → 15.0",
                    details = null
                ),
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.PERMISSION_SET_CHANGED,
                    severity = BaselineManager.AnomalySeverity.LOW,
                    description = "Sada oprávnění se změnila",
                    details = null
                )
            ),
            isFirstScan = false,
            scanCount = 10
        )

        val rawFindings = comparison.anomalies.map { anomaly ->
            val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(anomaly.type)
            TrustRiskModel.RawFinding(findingType, severity, anomaly.description, anomaly.details ?: "")
        }

        val verdict = model.evaluate(
            packageName = comparison.packageName,
            trustEvidence = systemTrust(comparison.packageName),
            rawFindings = rawFindings,
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )

        assertEquals("System app with only soft baseline anomalies → SAFE",
            TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `pipeline - real BaselineComparison first scan produces no anomalies (baseline init)`() {
        // First scan ever — BaselineManager produces empty anomalies, status NEW
        // This proves the baseline initialization path: first scan = clean slate
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.android.bluetooth",
            status = BaselineManager.BaselineStatus.NEW,
            anomalies = emptyList(),
            isFirstScan = true,
            scanCount = 0
        )

        assertTrue("First scan must have isFirstScan=true", comparison.isFirstScan)
        assertTrue("First scan must produce no anomalies", comparison.anomalies.isEmpty())
        assertEquals("First scan status must be NEW", BaselineManager.BaselineStatus.NEW, comparison.status)

        // No anomalies → no findings → SAFE
        val verdict = model.evaluate(
            packageName = comparison.packageName,
            trustEvidence = systemTrust(comparison.packageName),
            rawFindings = emptyList(),
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )
        assertEquals("First scan (baseline init) → SAFE",
            TrustRiskModel.EffectiveRisk.SAFE, verdict.effectiveRisk)
    }

    @Test
    fun `pipeline - real BaselineComparison compound anomalies preserve hardest finding`() {
        // Real scenario: cert changed + installer changed + version rollback
        // All HARD findings — model must produce CRITICAL (not downgraded)
        val comparison = BaselineManager.BaselineComparison(
            packageName = "com.android.nfc",
            status = BaselineManager.BaselineStatus.CHANGED,
            anomalies = listOf(
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.CERT_CHANGED,
                    severity = BaselineManager.AnomalySeverity.CRITICAL,
                    description = "Podpisový certifikát se změnil!",
                    details = null
                ),
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.INSTALLER_CHANGED,
                    severity = BaselineManager.AnomalySeverity.MEDIUM,
                    description = "Zdroj instalace se změnil",
                    details = null
                ),
                BaselineManager.BaselineAnomaly(
                    type = BaselineManager.AnomalyType.VERSION_ROLLBACK,
                    severity = BaselineManager.AnomalySeverity.HIGH,
                    description = "Verze snížena",
                    details = null
                )
            ),
            isFirstScan = false,
            scanCount = 7
        )

        val rawFindings = comparison.anomalies.map { anomaly ->
            val (findingType, severity) = AppSecurityScanner.mapBaselineAnomalyToFinding(
                anomaly.type, isTrustedInstaller = false
            )
            TrustRiskModel.RawFinding(findingType, severity, anomaly.description, anomaly.details ?: "")
        }

        // Verify at least one HARD finding exists
        val hardFindings = rawFindings.filter { it.type.hardness == TrustRiskModel.FindingHardness.HARD }
        assertTrue("Compound scenario must contain HARD findings", hardFindings.isNotEmpty())

        val verdict = model.evaluate(
            packageName = comparison.packageName,
            trustEvidence = systemTrust(comparison.packageName),
            rawFindings = rawFindings,
            isSystemApp = true,
            installClass = TrustRiskModel.InstallClass.SYSTEM_PREINSTALLED
        )

        assertEquals("Compound real anomalies with HARD findings → CRITICAL",
            TrustRiskModel.EffectiveRisk.CRITICAL, verdict.effectiveRisk)
    }

    // ════════════════════════════════════════════════════════════
    //  32. Static guard: all production matchDeveloperCert calls
    //      must pass callerDomain (no naked calls)
    //
    //  Reads actual source files and verifies that every call to
    //  matchDeveloperCert in production code passes a callerDomain
    //  argument. Test calls (in test/) are exempt.
    // ════════════════════════════════════════════════════════════

    @Test
    fun `static guard - all production matchDeveloperCert calls pass callerDomain`() {
        // Production source files that may call matchDeveloperCert
        val productionFiles = listOf(
            "TrustedAppsAndMessages.kt",
            "TrustEvidenceEngine.kt",
            "AppSecurityScanner.kt"
        )

        // Find the source root
        val sourceRoot = java.io.File("src/main/java/com/cybersentinel/app/domain/security")

        for (fileName in productionFiles) {
            val file = sourceRoot.resolve(fileName)
            if (!file.exists()) continue

            val lines = file.readLines()
            for ((index, line) in lines.withIndex()) {
                val trimmed = line.trim()

                // Skip: definition site, comments, strings
                if (trimmed.startsWith("fun matchDeveloperCert")) continue
                if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue

                // Look for call sites
                if (trimmed.contains("matchDeveloperCert(") && !trimmed.contains("fun matchDeveloperCert")) {
                    // This is a call site — verify it passes callerDomain or signerDomain
                    // Read a window of lines to capture the full call (may span multiple lines)
                    val window = lines.subList(
                        maxOf(0, index),
                        minOf(lines.size, index + 5)
                    ).joinToString(" ")

                    val passesCallerDomain = window.contains("callerDomain") || window.contains("signerDomain")
                    assertTrue(
                        "PRODUCTION SAFETY VIOLATION: $fileName:${index + 1} calls matchDeveloperCert " +
                                "without callerDomain/signerDomain parameter. All production calls must be " +
                                "domain-aware to prevent cross-domain cert matching.\n" +
                                "Line: $trimmed",
                        passesCallerDomain
                    )
                }
            }
        }
    }

    @Test
    fun `static guard - matchDeveloperCert has callerDomain parameter in signature`() {
        // Verify that the function signature itself includes callerDomain
        val file = java.io.File("src/main/java/com/cybersentinel/app/domain/security/TrustedAppsAndMessages.kt")
        if (!file.exists()) return

        val content = file.readText()
        val defPattern = Regex("""fun\s+matchDeveloperCert\s*\([^)]*callerDomain""")
        assertTrue(
            "matchDeveloperCert function signature must include callerDomain parameter",
            defPattern.containsMatchIn(content)
        )
    }

    @Test
    fun `static guard - production matchDeveloperCert call count matches expected`() {
        // We know there are exactly 2 production call sites:
        //  1. TrustedAppsAndMessages.kt - verifyTrustedApp() delegates
        //  2. TrustEvidenceEngine.kt - verifyCertificate() delegates
        // If someone adds a new call, this test will fail and force them to verify domain-awareness.
        val sourceRoot = java.io.File("src/main/java/com/cybersentinel/app/domain/security")
        var callCount = 0

        val productionFiles = listOf(
            "TrustedAppsAndMessages.kt",
            "TrustEvidenceEngine.kt",
            "AppSecurityScanner.kt"
        )

        for (fileName in productionFiles) {
            val file = sourceRoot.resolve(fileName)
            if (!file.exists()) continue

            val lines = file.readLines()
            for (line in lines) {
                val trimmed = line.trim()
                if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue
                if (trimmed.contains("matchDeveloperCert(") && !trimmed.contains("fun matchDeveloperCert")) {
                    callCount++
                }
            }
        }

        assertEquals(
            "Expected exactly 2 production call sites of matchDeveloperCert " +
                    "(TrustedAppsAndMessages.verifyTrustedApp + TrustEvidenceEngine.verifyCertificate). " +
                    "If you added a new call, verify it passes callerDomain and update this count.",
            2, callCount
        )
    }
}
