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
}
