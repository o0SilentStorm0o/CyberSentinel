package com.cybersentinel.app.domain.security

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Trust & Risk Model v4 — Production-grade 3-axis evidence-based evaluation.
 *
 * Design principles:
 *  1. Conservative on false positives — NEEDS_ATTENTION < 5% on a normal phone
 *  2. Aggressive on genuine threats — CRITICAL for hard findings + combos
 *  3. Stable between scans — same app, same state = same verdict
 *  4. Population-aware — system apps have different norms than user-installed apps
 *
 * 3-axis evaluation:
 *  Axis A: Identity & Provenance (Trust) — who is it and where did it come from?
 *  Axis B: Capability Profile — what can it do? (high-risk clusters vs privacy capabilities)
 *  Axis C: Change / Anomaly (Baseline) — what changed since last scan?
 *
 * Key rules:
 *  - HARD findings are NEVER suppressed by trust or category
 *  - High-risk clusters alone = INFO (privacy capability info)
 *  - NEEDS_ATTENTION requires COMBO: low trust + high-risk cluster + extra signal
 *  - Unknown category = default-safe mode (clusters → INFO, not alarm)
 *  - Privacy capabilities (camera, mic, contacts, location) = NEVER an alarm
 *  - System preinstalled apps use SYSTEM policy profile: hygiene findings (old SDK,
 *    exported components, over-privileged) are suppressed — only hard evidence triggers alarm
 *
 * 4-state output: Safe / Info / NeedsAttention / Critical
 */
@Singleton
class TrustRiskModel @Inject constructor() {

    // ══════════════════════════════════════════════════════════
    //  Install class — distinguishes "new to baseline" from "genuinely new install"
    // ══════════════════════════════════════════════════════════

    /**
     * Classifies how an app arrived on the device.
     *
     * SYSTEM_PREINSTALLED: shipped with the ROM (FLAG_SYSTEM, installer null/"android",
     *   firstInstallTime near device epoch). These are NEVER "new installs" — when they
     *   first appear in a scan it's because the user toggled system visibility, not
     *   because anything changed on the device.
     *
     * USER_INSTALLED: explicitly installed by the user (Play Store, sideload, etc.)
     *
     * ENTERPRISE_MANAGED: pushed via MDM / device-owner policy
     */
    enum class InstallClass {
        SYSTEM_PREINSTALLED,
        USER_INSTALLED,
        ENTERPRISE_MANAGED
    }

    /**
     * Policy profile — different populations need different thresholds.
     *
     * USER: default thresholds (current behavior)
     * SYSTEM: higher tolerance for hygiene findings (old SDK, exported components,
     *   over-privileged). Only hard evidence (cert change, suspicious installer,
     *   hooking frameworks) triggers escalation.
     */
    enum class PolicyProfile {
        USER,
        SYSTEM
    }

    /**
     * Determine install class from available evidence.
     */
    fun classifyInstall(
        isSystemApp: Boolean,
        installerType: TrustEvidenceEngine.InstallerType,
        partition: TrustEvidenceEngine.AppPartition
    ): InstallClass = when {
        installerType == TrustEvidenceEngine.InstallerType.MDM_INSTALLER -> InstallClass.ENTERPRISE_MANAGED
        isSystemApp || partition in setOf(
            TrustEvidenceEngine.AppPartition.SYSTEM,
            TrustEvidenceEngine.AppPartition.VENDOR,
            TrustEvidenceEngine.AppPartition.PRODUCT
        ) -> InstallClass.SYSTEM_PREINSTALLED
        else -> InstallClass.USER_INSTALLED
    }

    /**
     * Determine policy profile from install class.
     */
    fun policyProfileFor(installClass: InstallClass): PolicyProfile = when (installClass) {
        InstallClass.SYSTEM_PREINSTALLED -> PolicyProfile.SYSTEM
        InstallClass.ENTERPRISE_MANAGED -> PolicyProfile.SYSTEM  // MDM apps get system treatment
        InstallClass.USER_INSTALLED -> PolicyProfile.USER
    }

    // ══════════════════════════════════════════════════════════
    //  Finding classification
    // ══════════════════════════════════════════════════════════

    enum class FindingHardness {
        /** Never suppressed by trust. Always shown regardless of TrustScore. */
        HARD,
        /** Trust can reduce severity/weight. May be hidden for high-trust apps. */
        SOFT,
        /** Only alarming in combination with other signals. Alone = just info. */
        WEAK_SIGNAL
    }

    enum class FindingType(val hardness: FindingHardness) {
        // ── HARD findings (never suppressed, always override category/trust) ──
        DEBUG_SIGNATURE(FindingHardness.HARD),
        SIGNATURE_MISMATCH(FindingHardness.HARD),
        /** Signing cert changed vs baseline — integrity drift. HARD regardless of domain. */
        SIGNATURE_DRIFT(FindingHardness.HARD),
        BASELINE_SIGNATURE_CHANGE(FindingHardness.HARD),
        BASELINE_NEW_SYSTEM_APP(FindingHardness.HARD),
        INTEGRITY_FAIL_WITH_HOOKING(FindingHardness.HARD),
        INSTALLER_ANOMALY(FindingHardness.HARD),
        /** Sideloaded but cert matches known developer — likely power-user install (APKMirror, beta) */
        INSTALLER_ANOMALY_VERIFIED(FindingHardness.SOFT),
        /** Version rollback (downgrade attack) — HARD */
        VERSION_ROLLBACK(FindingHardness.HARD),
        /** Version rollback from trusted source — likely user-initiated, SOFT */
        VERSION_ROLLBACK_TRUSTED(FindingHardness.SOFT),

        // ── SOFT findings (trust-adjustable) ──
        OVER_PRIVILEGED(FindingHardness.SOFT),
        OLD_TARGET_SDK(FindingHardness.SOFT),
        /**
         * App is not signed with the Play Store key but that is EXPECTED
         * for its trust domain (platform / APEX / OEM).  Informational only.
         * Never triggers R1 hard-finding rule because hardness = SOFT.
         */
        NOT_PLAY_SIGNED(FindingHardness.SOFT),
        /** System component running from unexpected partition (e.g. /data/app) */
        PARTITION_ANOMALY(FindingHardness.HARD),
        
        // ── Change findings (baseline delta — severity depends on context) ──
        /** High-risk permission added between scans — HARD */
        HIGH_RISK_PERMISSION_ADDED(FindingHardness.HARD),
        /** Exported unprotected surface increased — SOFT */
        EXPORTED_SURFACE_INCREASED(FindingHardness.SOFT),

        // ── WEAK SIGNALS (only alarming in combos, alone = info) ──
        EXPORTED_COMPONENTS(FindingHardness.WEAK_SIGNAL),
        SUSPICIOUS_NATIVE_LIB(FindingHardness.WEAK_SIGNAL),
        /** High-risk capability cluster — info unless combo matches */
        HIGH_RISK_CAPABILITY(FindingHardness.WEAK_SIGNAL),
        /** Individual permission — NEVER an alarm alone */
        CRITICAL_PERMISSION(FindingHardness.WEAK_SIGNAL)
    }

    // ══════════════════════════════════════════════════════════
    //  Capability Clusters: high-risk vs privacy
    // ══════════════════════════════════════════════════════════

    /**
     * HIGH-RISK clusters: genuinely dangerous capabilities.
     * These can trigger NEEDS_ATTENTION when combined with low trust + extra signals.
     *
     * PRIVACY clusters (camera, mic, contacts, location, calendar, storage)
     * are NOT represented here — they are informational only and never alarm.
     */
    enum class CapabilityCluster(val label: String, val permissions: Set<String>, val isHighRisk: Boolean) {
        SMS("SMS přístup", setOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS"
        ), isHighRisk = true),
        CALL_LOG("Historie hovorů", setOf(
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS"
        ), isHighRisk = true),
        ACCESSIBILITY("Usnadnění přístupu", setOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ), isHighRisk = true),
        NOTIFICATION_LISTENER("Čtení notifikací", setOf(
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        ), isHighRisk = true),
        DEVICE_ADMIN("Správa zařízení", setOf(
            "android.permission.BIND_DEVICE_ADMIN"
        ), isHighRisk = true),
        VPN("VPN služba", setOf(
            "android.permission.BIND_VPN_SERVICE"
        ), isHighRisk = true),
        OVERLAY("Překrytí obrazovky", setOf(
            "android.permission.SYSTEM_ALERT_WINDOW"
        ), isHighRisk = true),
        INSTALL_PACKAGES("Instalace aplikací", setOf(
            "android.permission.REQUEST_INSTALL_PACKAGES"
        ), isHighRisk = true),
        BACKGROUND_LOCATION("Poloha na pozadí", setOf(
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        ), isHighRisk = false); // Background location = privacy, not inherently malicious

        fun isActive(permissions: Collection<String>): Boolean =
            permissions.any { it in this.permissions }
    }

    // ══════════════════════════════════════════════════════════
    //  Dangerous Combos (AND logic — need multiple signals)
    // ══════════════════════════════════════════════════════════

    data class DangerousCombo(
        val name: String,
        val requiredClusters: Set<CapabilityCluster>,
        val requiresLowTrust: Boolean = false,
        val requiresSideload: Boolean = false,
        val requiresDebugCert: Boolean = false,
        /** If true, combo doesn't apply when cluster is expected for category */
        val respectCategoryWhitelist: Boolean = true,
        val severity: AppSecurityScanner.RiskLevel
    )

    private val dangerousCombos = listOf(
        // Sideload + debug cert + SMS → CRITICAL (classic spyware)
        DangerousCombo(
            name = "Podezřelý SMS přístup",
            requiredClusters = setOf(CapabilityCluster.SMS),
            requiresSideload = true,
            requiresDebugCert = true,
            respectCategoryWhitelist = false, // hard rule — debug+sideload+SMS is always bad
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Sideload + accessibility + overlay → CRITICAL (accessibility attack)
        DangerousCombo(
            name = "Podezřelá kombinace overlay + accessibility",
            requiredClusters = setOf(CapabilityCluster.ACCESSIBILITY, CapabilityCluster.OVERLAY),
            requiresSideload = true,
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Accessibility + install packages + low trust → CRITICAL (dropper)
        DangerousCombo(
            name = "Podezřelá kombinace: může instalovat apps s accessibility",
            requiredClusters = setOf(CapabilityCluster.ACCESSIBILITY, CapabilityCluster.INSTALL_PACKAGES),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Low trust + SMS + call log → HIGH
        DangerousCombo(
            name = "Neověřená app s přístupem k SMS a hovorům",
            requiredClusters = setOf(CapabilityCluster.SMS, CapabilityCluster.CALL_LOG),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // Low trust + device admin → HIGH
        DangerousCombo(
            name = "Neověřená app se správou zařízení",
            requiredClusters = setOf(CapabilityCluster.DEVICE_ADMIN),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // Background location + accessibility + low trust → HIGH (stalkerware)
        DangerousCombo(
            name = "Sledování polohy s accessibility přístupem",
            requiredClusters = setOf(CapabilityCluster.BACKGROUND_LOCATION, CapabilityCluster.ACCESSIBILITY),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // Low trust + notification listener + overlay → HIGH (phishing pattern)
        DangerousCombo(
            name = "Podezřelá kombinace: čtení notifikací + overlay",
            requiredClusters = setOf(CapabilityCluster.NOTIFICATION_LISTENER, CapabilityCluster.OVERLAY),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // ── New combos (red-team hardening) ──
        // Accessibility + notification listener + sideloaded → CRITICAL (confirmed stalkerware)
        DangerousCombo(
            name = "Stalkerware: accessibility + čtení notifikací + sideload",
            requiredClusters = setOf(CapabilityCluster.ACCESSIBILITY, CapabilityCluster.NOTIFICATION_LISTENER),
            requiresLowTrust = true,
            requiresSideload = true,
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Accessibility + notification listener + low trust (without sideload) → HIGH (suspected stalkerware)
        DangerousCombo(
            name = "Podezření na stalkerware: accessibility + čtení notifikací",
            requiredClusters = setOf(CapabilityCluster.ACCESSIBILITY, CapabilityCluster.NOTIFICATION_LISTENER),
            requiresLowTrust = true,
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // Sideloaded + install packages → HIGH (dropper without accessibility)
        DangerousCombo(
            name = "Sideload s instalací aplikací",
            requiredClusters = setOf(CapabilityCluster.INSTALL_PACKAGES),
            requiresSideload = true,
            respectCategoryWhitelist = false, // sideload + install_packages is always suspicious
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),
        // Sideloaded VPN + low trust → HIGH (VPN used for traffic interception)
        DangerousCombo(
            name = "Podezřelá VPN z neznámého zdroje",
            requiredClusters = setOf(CapabilityCluster.VPN),
            requiresSideload = true,
            requiresLowTrust = true,
            respectCategoryWhitelist = false, // sideloaded VPN is always suspicious regardless of category
            severity = AppSecurityScanner.RiskLevel.HIGH
        ),

        // ── Dropper/Loader combos (timeline-aware patterns) ──
        // Overlay + install packages + low trust → CRITICAL (dropper staging overlay attack)
        DangerousCombo(
            name = "Dropper: overlay + instalace aplikací + nízká důvěra",
            requiredClusters = setOf(CapabilityCluster.OVERLAY, CapabilityCluster.INSTALL_PACKAGES),
            requiresLowTrust = true,
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Overlay + accessibility + sideloaded → CRITICAL (banking overlay attack)
        // Note: This extends the existing overlay+accessibility combo with sideload
        DangerousCombo(
            name = "Bankovní overlay útok: overlay + accessibility + sideload",
            requiredClusters = setOf(CapabilityCluster.OVERLAY, CapabilityCluster.ACCESSIBILITY),
            requiresSideload = true,
            requiresLowTrust = true,
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // SMS + install packages + sideloaded → CRITICAL (SMS-based dropper/C2)
        DangerousCombo(
            name = "SMS dropper: SMS + instalace + sideload",
            requiredClusters = setOf(CapabilityCluster.SMS, CapabilityCluster.INSTALL_PACKAGES),
            requiresSideload = true,
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        ),
        // Accessibility + overlay + install packages → CRITICAL (full dropper toolkit)
        DangerousCombo(
            name = "Plný dropper: accessibility + overlay + instalace",
            requiredClusters = setOf(
                CapabilityCluster.ACCESSIBILITY,
                CapabilityCluster.OVERLAY,
                CapabilityCluster.INSTALL_PACKAGES
            ),
            respectCategoryWhitelist = false,
            severity = AppSecurityScanner.RiskLevel.CRITICAL
        )
    )

    // ══════════════════════════════════════════════════════════
    //  Category → expected high-risk cluster whitelist
    // ══════════════════════════════════════════════════════════

    /**
     * Which high-risk clusters are EXPECTED (not alarming) for each category.
     * If a cluster is whitelisted for a category, it won't trigger NEEDS_ATTENTION
     * even with low trust — it will stay INFO.
     */
    private val categoryClusterWhitelist: Map<AppCategoryDetector.AppCategory, Set<CapabilityCluster>> = mapOf(
        // ── System categories: broad whitelists (these ARE the system) ──
        AppCategoryDetector.AppCategory.SYSTEM_TELECOM to setOf(
            CapabilityCluster.SMS, CapabilityCluster.CALL_LOG,
            CapabilityCluster.NOTIFICATION_LISTENER, CapabilityCluster.BACKGROUND_LOCATION
        ),
        AppCategoryDetector.AppCategory.SYSTEM_MESSAGING to setOf(
            CapabilityCluster.SMS
        ),
        AppCategoryDetector.AppCategory.SYSTEM_FRAMEWORK to setOf(
            CapabilityCluster.OVERLAY, CapabilityCluster.ACCESSIBILITY,
            CapabilityCluster.NOTIFICATION_LISTENER, CapabilityCluster.DEVICE_ADMIN,
            CapabilityCluster.INSTALL_PACKAGES
        ),
        AppCategoryDetector.AppCategory.SYSTEM_CONNECTIVITY to setOf(
            CapabilityCluster.VPN, CapabilityCluster.BACKGROUND_LOCATION
        ),

        // ── User categories: targeted whitelists ──
        // Phone/Dialer: SMS + call log is their job
        AppCategoryDetector.AppCategory.PHONE_DIALER to setOf(
            CapabilityCluster.SMS, CapabilityCluster.CALL_LOG
        ),
        // VPN apps: VPN service is their job
        AppCategoryDetector.AppCategory.VPN to setOf(
            CapabilityCluster.VPN
        ),
        // Security apps: VPN, notification listener can be expected
        AppCategoryDetector.AppCategory.SECURITY to setOf(
            CapabilityCluster.VPN, CapabilityCluster.NOTIFICATION_LISTENER
        ),
        // Accessibility tools: accessibility is their job
        AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL to setOf(
            CapabilityCluster.ACCESSIBILITY
        ),
        // Launcher: overlay is common for launchers
        AppCategoryDetector.AppCategory.LAUNCHER to setOf(
            CapabilityCluster.OVERLAY, CapabilityCluster.NOTIFICATION_LISTENER
        ),
        // Keyboard: notification listener sometimes used
        AppCategoryDetector.AppCategory.KEYBOARD to setOf(
            CapabilityCluster.NOTIFICATION_LISTENER
        )
        // Messaging: SMS is NOT whitelisted — only system dialers get that pass
        // Banking: nothing is whitelisted — banks don't need SMS/accessibility
    )

    /**
     * Check if a high-risk cluster is expected for this app's category.
     * Special rule: ACCESSIBILITY_TOOL category only whitelists accessibility
     * when trust is at least moderate (≥40). A low-trust sideloaded
     * "accessibility tool" should still raise concerns.
     */
    fun isClusterExpectedForCategory(
        cluster: CapabilityCluster,
        category: AppCategoryDetector.AppCategory,
        trustScore: Int = 100 // default = fully trusted (backward compat)
    ): Boolean {
        val isWhitelisted = categoryClusterWhitelist[category]?.contains(cluster) == true
        // Accessibility tool with low trust: don't whitelist accessibility cluster
        if (isWhitelisted && category == AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL
            && cluster == CapabilityCluster.ACCESSIBILITY && trustScore < 40) {
            return false
        }
        return isWhitelisted
    }

    // ══════════════════════════════════════════════════════════
    //  AppVerdict — final 4-state output
    // ══════════════════════════════════════════════════════════

    data class AppVerdict(
        val packageName: String,
        val trustScore: Int,
        val riskScore: Int,
        val effectiveRisk: EffectiveRisk,
        val verdictLabel: String,
        val verdictDescription: String,
        val shouldShowInMainList: Boolean,
        val isSystemComponent: Boolean,
        val adjustedFindings: List<AdjustedFinding>,
        val activeClusters: List<CapabilityCluster> = emptyList(),
        val matchedCombos: List<String> = emptyList(),
        val privacyCapabilities: List<String> = emptyList(),
        /** Top 2-3 reasons for the verdict, sorted by explainPriority. For UX display. */
        val topReasons: List<String> = emptyList()
    )

    data class AdjustedFinding(
        val findingType: FindingType,
        val originalSeverity: AppSecurityScanner.RiskLevel,
        val adjustedSeverity: AppSecurityScanner.RiskLevel,
        val hardness: FindingHardness,
        val wasDowngraded: Boolean,
        val title: String,
        /** Priority for UX display: lower = more important. Used to limit reasons shown to user. */
        val explainPriority: Int = 99
    )

    /**
     * 4-state verdict
     */
    enum class EffectiveRisk(val label: String, val emoji: String) {
        /** Genuine threat — hard findings, dangerous combos, or high risk + low trust */
        CRITICAL("Vyžaduje pozornost", "🔴"),
        /** Worth reviewing — combo match, change detected, or moderate concern */
        NEEDS_ATTENTION("Ke kontrole", "🟠"),
        /** Informational — has capabilities worth knowing about, but no alarm */
        INFO("Informace", "🔵"),
        /** No actionable findings */
        SAFE("Bezpečná", "🟢")
    }

    // ══════════════════════════════════════════════════════════
    //  Main evaluation logic (3-axis)
    // ══════════════════════════════════════════════════════════

    fun evaluate(
        packageName: String,
        trustEvidence: TrustEvidenceEngine.TrustEvidence,
        rawFindings: List<RawFinding>,
        isSystemApp: Boolean,
        grantedPermissions: List<String> = emptyList(),
        appCategory: AppCategoryDetector.AppCategory = AppCategoryDetector.AppCategory.OTHER,
        /** True only for USER_INSTALLED apps that appeared since the last scan.
         *  SYSTEM_PREINSTALLED apps that are "new to baseline" NEVER get this flag. */
        isNewApp: Boolean = false,
        /** Real enabled state of special access — null means legacy mode (manifest-only) */
        specialAccessSnapshot: SpecialAccessInspector.SpecialAccessSnapshot? = null,
        /** Install class — drives policy profile selection.  Defaults to USER_INSTALLED
         *  for backward compatibility with existing call sites / tests. */
        installClass: InstallClass = InstallClass.USER_INSTALLED,
        /** Explicit policy profile override. If null, derived from installClass. */
        policyProfileOverride: PolicyProfile? = null
    ): AppVerdict {
        val policyProfile = policyProfileOverride ?: policyProfileFor(installClass)

        // ── Axis A: Trust tiers ──
        val isHighTrust = trustEvidence.trustScore >= 70
        val isModerateTrust = trustEvidence.trustScore in 40..69
        val isLowTrust = trustEvidence.trustScore < 40
        val installerType = trustEvidence.installerInfo.installerType
        // CRITICAL distinction: UNKNOWN installer ≠ SIDELOADED
        val isDefinitelySideloaded = installerType == TrustEvidenceEngine.InstallerType.SIDELOADED
        val hasDebugCert = rawFindings.any { it.type == FindingType.DEBUG_SIGNATURE }
        val isUnknownCategory = appCategory == AppCategoryDetector.AppCategory.OTHER

        // ── Axis B: Capability profile ──
        // When specialAccessSnapshot is available, special-access clusters are ONLY active
        // when the service is actually enabled (not just declared in manifest).
        // This dramatically reduces false positives — a manifest declaration alone is harmless.
        val activeClusters = CapabilityCluster.entries.filter { cluster ->
            val hasManifestPermission = cluster.isActive(grantedPermissions)
            if (!hasManifestPermission) return@filter false

            // For special-access clusters, check REAL enabled state
            if (specialAccessSnapshot != null) {
                when (cluster) {
                    CapabilityCluster.ACCESSIBILITY ->
                        specialAccessSnapshot.accessibilityEnabled
                    CapabilityCluster.NOTIFICATION_LISTENER ->
                        specialAccessSnapshot.notificationListenerEnabled
                    CapabilityCluster.DEVICE_ADMIN ->
                        specialAccessSnapshot.deviceAdminEnabled
                    CapabilityCluster.OVERLAY ->
                        specialAccessSnapshot.overlayEnabled
                    // Non-special-access clusters: manifest permission is sufficient
                    else -> true
                }
            } else {
                // Legacy mode: no snapshot available, fall back to manifest-only
                true
            }
        }
        val activeHighRiskClusters = activeClusters.filter { it.isHighRisk }
        // Clusters that are NOT expected for this category
        val unexpectedHighRiskClusters = activeHighRiskClusters.filterNot {
            isClusterExpectedForCategory(it, appCategory, trustEvidence.trustScore)
        }
        val hasUnexpectedHighRiskCluster = unexpectedHighRiskClusters.isNotEmpty()

        // Check dangerous combos (with category awareness)
        val matchedCombos = dangerousCombos.filter { combo ->
            val clustersMatch = combo.requiredClusters.all { cluster -> cluster in activeClusters }
            val trustMatch = !combo.requiresLowTrust || isLowTrust
            val sideloadMatch = !combo.requiresSideload || isDefinitelySideloaded
            val debugMatch = !combo.requiresDebugCert || hasDebugCert
            // If combo respects category whitelist, check if ALL required clusters are expected
            val categoryMatch = if (combo.respectCategoryWhitelist) {
                // At least one required cluster must NOT be expected for category
                combo.requiredClusters.any { !isClusterExpectedForCategory(it, appCategory, trustEvidence.trustScore) }
            } else true // Hard combos (debug+sideload) ignore category
            clustersMatch && trustMatch && sideloadMatch && debugMatch && categoryMatch
        }

        // Privacy capabilities (informational — NEVER an alarm)
        val privacyCapabilities = buildPrivacyCapabilities(grantedPermissions, appCategory)

        // ── Axis C: Change / anomaly assessment ──
        val hasBaselineDelta = rawFindings.any {
            it.type in setOf(
                FindingType.HIGH_RISK_PERMISSION_ADDED,
                FindingType.BASELINE_SIGNATURE_CHANGE,
                FindingType.BASELINE_NEW_SYSTEM_APP,
                FindingType.EXPORTED_SURFACE_INCREASED,
                FindingType.VERSION_ROLLBACK
            )
        }
        val hasHighRiskPermAdded = rawFindings.any { it.type == FindingType.HIGH_RISK_PERMISSION_ADDED }
        val hasSurfaceIncrease = rawFindings.any { it.type == FindingType.EXPORTED_SURFACE_INCREASED }

        // ── Adjust findings (trust-aware + policy-profile-aware) ──
        val adjustedFindings = rawFindings.map { finding ->
            adjustFinding(finding, trustEvidence, policyProfile)
        }

        // ── Compute numeric risk score ──
        val riskScore = calculateRiskScore(rawFindings, matchedCombos)

        // ══════════════════════════════════════════════════════
        //  VERDICT DECISION — strict priority chain
        // ══════════════════════════════════════════════════════

        // Step 1: Hard findings — ALWAYS CRITICAL (trust/category/policy NEVER overrides)
        val hasHardFindings = adjustedFindings.any {
            it.hardness == FindingHardness.HARD &&
            it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score
        }

        // Step 2: Anomalous trust — ALWAYS CRITICAL
        val isAnomalous = trustEvidence.trustLevel == TrustEvidenceEngine.TrustLevel.ANOMALOUS

        // Step 3: Dangerous combo severity
        val highestComboSeverity = matchedCombos.maxOfOrNull { it.severity.score } ?: 0

        // Step 4: "Extra signals" — used for combo-gating of NEEDS_ATTENTION
        // A cluster alone is NOT enough. Need cluster + at least one extra signal.
        // NOTE: isNewApp is ONLY true for USER_INSTALLED (never system preinstalled).
        val hasExtraSignal = hasBaselineDelta ||
                isDefinitelySideloaded ||
                isNewApp ||
                rawFindings.any { it.type == FindingType.SUSPICIOUS_NATIVE_LIB } ||
                rawFindings.any { it.type == FindingType.INSTALLER_ANOMALY } ||
                rawFindings.any { it.type == FindingType.EXPORTED_SURFACE_INCREASED }

        // Step 4b: Installer changed to sideload + high-risk cluster → escalate
        val hasInstallerAnomaly = rawFindings.any { it.type == FindingType.INSTALLER_ANOMALY }
        val installerChangedWithHighRisk = hasInstallerAnomaly && activeHighRiskClusters.any {
            it in setOf(
                CapabilityCluster.ACCESSIBILITY, CapabilityCluster.NOTIFICATION_LISTENER,
                CapabilityCluster.VPN, CapabilityCluster.INSTALL_PACKAGES,
                CapabilityCluster.DEVICE_ADMIN
            )
        }

        // ── R10 threshold: policy-profile-aware ──
        // Instead of "any LOW finding → INFO", use weighted threshold.
        // SYSTEM profile needs higher bar because hygiene findings are noise for system apps.
        val meaningfulFindingWeight: Int = adjustedFindings.fold(0) { acc, f ->
            acc + if (f.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.LOW.score) {
                when (f.hardness) {
                    FindingHardness.HARD -> 10  // always meaningful
                    FindingHardness.SOFT -> when (f.findingType) {
                        // Hygiene findings: low weight for SYSTEM, normal for USER
                        FindingType.OLD_TARGET_SDK -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 3
                        FindingType.OVER_PRIVILEGED -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 3
                        FindingType.EXPORTED_SURFACE_INCREASED -> if (policyProfile == PolicyProfile.SYSTEM) 1 else 3
                        FindingType.INSTALLER_ANOMALY_VERIFIED -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 2
                        // NOT_PLAY_SIGNED: zero weight for SYSTEM (expected), low for USER
                        FindingType.NOT_PLAY_SIGNED -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 2
                        else -> 3
                    }
                    FindingHardness.WEAK_SIGNAL -> when (f.findingType) {
                        FindingType.EXPORTED_COMPONENTS -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 1
                        FindingType.HIGH_RISK_CAPABILITY -> if (policyProfile == PolicyProfile.SYSTEM) 0 else 1
                        else -> 1
                    }
                }
            } else 0
        }
        val infoThreshold = when (policyProfile) {
            PolicyProfile.SYSTEM -> 5   // System apps need real evidence to reach INFO
            PolicyProfile.USER -> 1     // User apps: any finding with weight ≥ 1 → INFO
        }

        val effectiveRisk = when {
            // ── CRITICAL tier ── (policy profile NEVER suppresses)
            // R1: Hard findings → CRITICAL (debug cert, cert mismatch, hooking, etc.)
            hasHardFindings -> EffectiveRisk.CRITICAL
            // R2: Anomalous trust → CRITICAL
            isAnomalous -> EffectiveRisk.CRITICAL
            // R3: CRITICAL combo → CRITICAL
            highestComboSeverity >= AppSecurityScanner.RiskLevel.CRITICAL.score -> EffectiveRisk.CRITICAL

            // ── NEEDS_ATTENTION tier ──
            // R4: HIGH combo → NEEDS_ATTENTION
            highestComboSeverity >= AppSecurityScanner.RiskLevel.HIGH.score -> EffectiveRisk.NEEDS_ATTENTION
            // R4b: Installer changed (e.g., Play→sideload) + dangerous cluster → NEEDS_ATTENTION
            installerChangedWithHighRisk -> EffectiveRisk.NEEDS_ATTENTION
            // R5: High-risk permission added + low trust → NEEDS_ATTENTION
            hasHighRiskPermAdded && isLowTrust -> EffectiveRisk.NEEDS_ATTENTION
            // R6: Low trust + unexpected high-risk cluster + extra signal → NEEDS_ATTENTION
            //     This is the key "combo gating" rule that prevents NEEDS_ATTENTION inflation.
            //     Cluster alone = INFO. Cluster + low trust alone = INFO. Need extra signal.
            isLowTrust && hasUnexpectedHighRiskCluster && hasExtraSignal -> EffectiveRisk.NEEDS_ATTENTION

            // ── INFO tier ──
            // R7: High-risk permission added (but moderate/high trust) → INFO
            hasHighRiskPermAdded -> EffectiveRisk.INFO
            // R8: Exported surface increase + low trust → INFO
            hasSurfaceIncrease && isLowTrust -> EffectiveRisk.INFO
            // R9: Has unexpected high-risk clusters but no extra signal → INFO
            //     "You have SMS access but nothing else suspicious" = just information
            hasUnexpectedHighRiskCluster && !isHighTrust -> EffectiveRisk.INFO
            // R10: Weighted threshold — replaces the old "any LOW → INFO" anti-pattern.
            //      For USER profile: threshold=1 (essentially any finding).
            //      For SYSTEM profile: threshold=5 (hygiene findings don't count).
            meaningfulFindingWeight >= infoThreshold -> EffectiveRisk.INFO

            // ── SAFE tier ──
            // R11: Everything else (including expected clusters, privacy caps)
            else -> EffectiveRisk.SAFE
        }

        // ── Determine which rule triggered ──
        val triggerRule = when {
            hasHardFindings -> "R1:HARD_FINDING"
            isAnomalous -> "R2:ANOMALOUS_TRUST"
            highestComboSeverity >= AppSecurityScanner.RiskLevel.CRITICAL.score -> "R3:CRIT_COMBO"
            highestComboSeverity >= AppSecurityScanner.RiskLevel.HIGH.score -> "R4:HIGH_COMBO"
            installerChangedWithHighRisk -> "R4b:INSTALLER_CHANGED_HIGHRISK"
            hasHighRiskPermAdded && isLowTrust -> "R5:HIGHRISK_PERM_LOWT"
            isLowTrust && hasUnexpectedHighRiskCluster && hasExtraSignal -> "R6:LOWT_CLUSTER_SIGNAL"
            hasHighRiskPermAdded -> "R7:HIGHRISK_PERM"
            hasSurfaceIncrease && isLowTrust -> "R8:SURFACE_LOWT"
            hasUnexpectedHighRiskCluster && !isHighTrust -> "R9:UNEXPECTED_CLUSTER"
            meaningfulFindingWeight >= infoThreshold -> "R10:WEIGHTED_THRESHOLD(w=$meaningfulFindingWeight,t=$infoThreshold)"
            else -> "R11:SAFE_DEFAULT"
        }

        // System apps: show in main list only on genuine concerns
        val shouldShowInMainList = if (isSystemApp) {
            hasHardFindings || effectiveRisk == EffectiveRisk.CRITICAL || hasHighRiskPermAdded
        } else {
            effectiveRisk in setOf(EffectiveRisk.CRITICAL, EffectiveRisk.NEEDS_ATTENTION)
        }

        val (label, description) = generateVerdictText(
            effectiveRisk, trustEvidence, isSystemApp, adjustedFindings, matchedCombos, appCategory
        )

        // Build top reasons for UX (max 3 for CRITICAL, max 2 for NEEDS_ATTENTION)
        val maxReasons = when (effectiveRisk) {
            EffectiveRisk.CRITICAL -> 3
            EffectiveRisk.NEEDS_ATTENTION -> 2
            else -> 0
        }
        val topReasons = if (maxReasons > 0) {
            val reasons = mutableListOf<String>()
            // 1. Combo matches are the most important reasons
            matchedCombos.take(2).forEach { reasons.add(it.name) }
            // 2. HARD findings
            adjustedFindings
                .filter { it.hardness == FindingHardness.HARD && it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.MEDIUM.score }
                .sortedBy { it.explainPriority }
                .take(maxReasons - reasons.size)
                .forEach { reasons.add(it.title) }
            // 3. Fill with SOFT findings if needed
            if (reasons.size < maxReasons) {
                adjustedFindings
                    .filter { it.hardness == FindingHardness.SOFT && it.adjustedSeverity.score >= AppSecurityScanner.RiskLevel.LOW.score }
                    .sortedBy { it.explainPriority }
                    .take(maxReasons - reasons.size)
                    .forEach { reasons.add(it.title) }
            }
            reasons.take(maxReasons)
        } else emptyList()

        return AppVerdict(
            packageName = packageName,
            trustScore = trustEvidence.trustScore,
            riskScore = riskScore,
            effectiveRisk = effectiveRisk,
            verdictLabel = label,
            verdictDescription = description,
            shouldShowInMainList = shouldShowInMainList,
            isSystemComponent = isSystemApp && trustEvidence.systemAppInfo.isSystemApp,
            adjustedFindings = adjustedFindings,
            activeClusters = activeClusters,
            matchedCombos = matchedCombos.map { it.name },
            privacyCapabilities = privacyCapabilities,
            topReasons = topReasons
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Finding adjustment (trust-aware)
    // ──────────────────────────────────────────────────────────

    private fun adjustFinding(
        finding: RawFinding,
        trust: TrustEvidenceEngine.TrustEvidence,
        policyProfile: PolicyProfile = PolicyProfile.USER
    ): AdjustedFinding {
        val hardness = finding.type.hardness

        // Explainability priority: HARD findings first, then by severity
        val basePriority = when (hardness) {
            FindingHardness.HARD -> 0
            FindingHardness.SOFT -> 10
            FindingHardness.WEAK_SIGNAL -> 20
        }
        val severityBonus = when (finding.severity) {
            AppSecurityScanner.RiskLevel.CRITICAL -> 0
            AppSecurityScanner.RiskLevel.HIGH -> 1
            AppSecurityScanner.RiskLevel.MEDIUM -> 2
            AppSecurityScanner.RiskLevel.LOW -> 3
            AppSecurityScanner.RiskLevel.NONE -> 4
        }
        val priority = basePriority + severityBonus

        // HARD findings: NEVER downgrade, regardless of trust, category, or policy
        if (hardness == FindingHardness.HARD) {
            return AdjustedFinding(
                findingType = finding.type,
                originalSeverity = finding.severity,
                adjustedSeverity = finding.severity,
                hardness = FindingHardness.HARD,
                wasDowngraded = false,
                title = finding.title,
                explainPriority = priority
            )
        }

        // ── SYSTEM policy: aggressively suppress hygiene findings ──
        if (policyProfile == PolicyProfile.SYSTEM) {
            val isHygieneFinding = finding.type in setOf(
                FindingType.OLD_TARGET_SDK,
                FindingType.OVER_PRIVILEGED,
                FindingType.EXPORTED_COMPONENTS,
                FindingType.HIGH_RISK_CAPABILITY,
                FindingType.INSTALLER_ANOMALY_VERIFIED,
                // NOT_PLAY_SIGNED is expected for system/APEX — always suppress
                FindingType.NOT_PLAY_SIGNED
            )
            if (isHygieneFinding) {
                return AdjustedFinding(
                    findingType = finding.type,
                    originalSeverity = finding.severity,
                    adjustedSeverity = AppSecurityScanner.RiskLevel.NONE,
                    hardness = hardness,
                    wasDowngraded = true,
                    title = finding.title,
                    explainPriority = priority + 50  // Push to bottom
                )
            }
        }

        // WEAK_SIGNAL: downgrade aggressively for trusted apps
        if (hardness == FindingHardness.WEAK_SIGNAL) {
            val adjustedSeverity = when {
                trust.trustScore >= 70 -> AppSecurityScanner.RiskLevel.NONE  // Invisible
                trust.trustScore >= 40 -> downgrade(finding.severity, 2)
                else -> downgrade(finding.severity, 1)
            }
            return AdjustedFinding(
                findingType = finding.type,
                originalSeverity = finding.severity,
                adjustedSeverity = adjustedSeverity,
                hardness = FindingHardness.WEAK_SIGNAL,
                wasDowngraded = adjustedSeverity != finding.severity,
                title = finding.title,
                explainPriority = priority
            )
        }

        // SOFT: standard trust-based downgrade
        val adjustedSeverity = when {
            trust.trustScore >= 70 -> downgrade(finding.severity, 2)
            trust.trustScore >= 40 -> downgrade(finding.severity, 1)
            else -> finding.severity
        }

        return AdjustedFinding(
            findingType = finding.type,
            originalSeverity = finding.severity,
            adjustedSeverity = adjustedSeverity,
            hardness = FindingHardness.SOFT,
            wasDowngraded = adjustedSeverity != finding.severity,
            title = finding.title,
            explainPriority = priority
        )
    }

    private fun downgrade(severity: AppSecurityScanner.RiskLevel, levels: Int): AppSecurityScanner.RiskLevel {
        val allLevels = AppSecurityScanner.RiskLevel.entries.sortedByDescending { it.score }
        val currentIdx = allLevels.indexOf(severity)
        val newIdx = (currentIdx + levels).coerceAtMost(allLevels.lastIndex)
        return allLevels[newIdx]
    }

    // ──────────────────────────────────────────────────────────
    //  Privacy capabilities (informational, NEVER alarm)
    // ──────────────────────────────────────────────────────────

    private fun buildPrivacyCapabilities(
        permissions: List<String>,
        category: AppCategoryDetector.AppCategory
    ): List<String> {
        val capabilities = mutableListOf<String>()
        val expected = category.expectedPermissions

        val capMap = mapOf(
            "android.permission.CAMERA" to "📷 Kamera",
            "android.permission.RECORD_AUDIO" to "🎤 Mikrofon",
            "android.permission.READ_CONTACTS" to "👥 Kontakty",
            "android.permission.ACCESS_FINE_LOCATION" to "📍 Přesná poloha",
            "android.permission.ACCESS_COARSE_LOCATION" to "📍 Přibližná poloha",
            "android.permission.READ_EXTERNAL_STORAGE" to "💾 Úložiště",
            "android.permission.WRITE_EXTERNAL_STORAGE" to "💾 Úložiště (zápis)",
            "android.permission.READ_CALENDAR" to "📅 Kalendář",
            "android.permission.BODY_SENSORS" to "📊 Senzory",
            "android.permission.BLUETOOTH_CONNECT" to "📶 Bluetooth"
        )

        for ((perm, label) in capMap) {
            if (perm in permissions) {
                val suffix = if (perm in expected) " (očekávané)" else ""
                capabilities.add("$label$suffix")
            }
        }
        return capabilities
    }

    // ──────────────────────────────────────────────────────────
    //  Risk scoring (numeric, for sorting/display)
    // ──────────────────────────────────────────────────────────

    private fun calculateRiskScore(
        findings: List<RawFinding>,
        combos: List<DangerousCombo>
    ): Int {
        var score = 0
        for (finding in findings) {
            score += when (finding.type.hardness) {
                FindingHardness.HARD -> when (finding.severity) {
                    AppSecurityScanner.RiskLevel.CRITICAL -> 30
                    AppSecurityScanner.RiskLevel.HIGH -> 20
                    AppSecurityScanner.RiskLevel.MEDIUM -> 10
                    else -> 5
                }
                FindingHardness.SOFT -> when (finding.severity) {
                    AppSecurityScanner.RiskLevel.CRITICAL -> 15
                    AppSecurityScanner.RiskLevel.HIGH -> 10
                    AppSecurityScanner.RiskLevel.MEDIUM -> 5
                    else -> 2
                }
                FindingHardness.WEAK_SIGNAL -> 0
            }
        }
        for (combo in combos) {
            score += when (combo.severity) {
                AppSecurityScanner.RiskLevel.CRITICAL -> 40
                AppSecurityScanner.RiskLevel.HIGH -> 25
                AppSecurityScanner.RiskLevel.MEDIUM -> 15
                else -> 5
            }
        }
        return score.coerceIn(0, 100)
    }

    // ──────────────────────────────────────────────────────────
    //  Verdict text generation
    // ──────────────────────────────────────────────────────────

    private fun generateVerdictText(
        risk: EffectiveRisk,
        trust: TrustEvidenceEngine.TrustEvidence,
        isSystem: Boolean,
        findings: List<AdjustedFinding>,
        combos: List<DangerousCombo>,
        category: AppCategoryDetector.AppCategory
    ): Pair<String, String> {
        val prefix = if (isSystem) "Systémová komponenta" else "Aplikace"

        return when (risk) {
            EffectiveRisk.CRITICAL -> {
                val comboNames = combos
                    .filter { it.severity.score >= AppSecurityScanner.RiskLevel.HIGH.score }
                    .map { it.name }
                when {
                    comboNames.isNotEmpty() ->
                        "Vyžaduje pozornost" to "$prefix má podezřelou kombinaci: ${comboNames.first()}"
                    findings.any { it.hardness == FindingHardness.HARD } ->
                        "Vyžaduje pozornost" to "$prefix vykazuje neobvyklé chování, které nelze vysvětlit důvěrou"
                    else ->
                        "Vyžaduje pozornost" to "$prefix má podezřelé chování při nízké úrovni důvěry"
                }
            }
            EffectiveRisk.NEEDS_ATTENTION -> {
                when {
                    findings.any { it.findingType == FindingType.HIGH_RISK_PERMISSION_ADDED } ->
                        "Změna oprávnění" to "$prefix získala nová riziková oprávnění od posledního skenování"
                    combos.isNotEmpty() ->
                        "Ke kontrole" to "$prefix má podezřelou kombinaci schopností: ${combos.first().name}"
                    trust.trustScore < 40 ->
                        "Ke kontrole" to "$prefix s nízkou důvěrou má citlivé schopnosti"
                    else ->
                        "Doporučujeme zkontrolovat" to "$prefix má nálezy, které stojí za kontrolu"
                }
            }
            EffectiveRisk.INFO -> {
                when {
                    trust.trustScore >= 70 ->
                        "Ověřená" to "$prefix od ověřeného vývojáře"
                    findings.any { it.findingType == FindingType.HIGH_RISK_PERMISSION_ADDED } ->
                        "Nová oprávnění" to "$prefix dostala nová oprávnění, ale pochází z důvěryhodného zdroje"
                    else ->
                        "Informace" to "$prefix má přístup k některým funkcím zařízení"
                }
            }
            EffectiveRisk.SAFE -> {
                "Bezpečná" to "$prefix splňuje bezpečnostní standardy"
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Input type
    // ══════════════════════════════════════════════════════════

    data class RawFinding(
        val type: FindingType,
        val severity: AppSecurityScanner.RiskLevel,
        val title: String,
        val description: String
    )
}
