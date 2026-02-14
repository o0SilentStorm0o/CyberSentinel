package com.cybersentinel.app.domain.security

/**
 * AppFeatureVector — structured knowledge base for each scanned app.
 *
 * This transforms the App Scanner from a "result producer" into a "knowledge base"
 * that future systems (RootCauseResolver, Sleeping Sentinel) can query.
 *
 * 5 feature groups:
 *  1. Identity — who is this app and how much do we trust it?
 *  2. Change — what changed since last scan?
 *  3. Capability — what dangerous things can it do?
 *  4. Surface — how exposed is it?
 *  5. SpecialAccess — what special access is ACTUALLY enabled?
 *
 * Design: Pure data class, no logic. Built by AppSecurityScanner after analysis.
 */
data class AppFeatureVector(
    val packageName: String,
    val timestamp: Long = System.currentTimeMillis(),

    // ── 1. Identity features ──
    val identity: IdentityFeatures,

    // ── 2. Change features (baseline delta) ──
    val change: ChangeFeatures,

    // ── 3. Capability features ──
    val capability: CapabilityFeatures,

    // ── 4. Surface features ──
    val surface: SurfaceFeatures,

    // ── 5. Special access features (REAL enabled state) ──
    val specialAccess: SpecialAccessInspector.SpecialAccessSnapshot,

    // ── Verdict summary ──
    val verdict: VerdictSummary
) {
    // ── 1. Identity ──
    data class IdentityFeatures(
        val trustScore: Int,
        val trustLevel: TrustEvidenceEngine.TrustLevel,
        val certSha256: String,
        val certMatchType: TrustEvidenceEngine.CertMatchType,
        val matchedDeveloper: String?,
        val installerType: TrustEvidenceEngine.InstallerType,
        val installerPackage: String?,
        val isSystemApp: Boolean,
        val isPlatformSigned: Boolean,
        val hasSigningLineage: Boolean,
        val isNewApp: Boolean
    )

    // ── 2. Change ──
    data class ChangeFeatures(
        val baselineStatus: BaselineManager.BaselineStatus,
        val isFirstScan: Boolean,
        val anomalies: List<BaselineManager.AnomalyType>,
        /** Timestamps for time correlation (null if not tracked yet) */
        val lastUpdateAt: Long? = null,
        val lastInstallerChangeAt: Long? = null,
        val lastHighRiskPermAddedAt: Long? = null,
        val lastSpecialAccessEnabledAt: Long? = null,
        /** Version info */
        val versionCode: Long = 0,
        val versionName: String? = null,
        /** True if version went DOWN (rollback) */
        val isVersionRollback: Boolean = false
    )

    // ── 3. Capability ──
    data class CapabilityFeatures(
        /** Active high-risk clusters (from manifest permissions) */
        val activeHighRiskClusters: List<TrustRiskModel.CapabilityCluster>,
        /** Clusters that are NOT expected for this app's category */
        val unexpectedClusters: List<TrustRiskModel.CapabilityCluster>,
        /** Total dangerous permissions granted */
        val dangerousPermissionCount: Int,
        /** High-risk permissions specifically (SMS, accessibility, etc.) */
        val highRiskPermissions: List<String>,
        /** Privacy capabilities (camera, mic, contacts, location) — informational */
        val privacyCapabilities: List<String>,
        /** Matched dangerous combos */
        val matchedCombos: List<String>,
        /** App category detected */
        val appCategory: AppCategoryDetector.AppCategory
    )

    // ── 4. Surface ──
    data class SurfaceFeatures(
        val exportedActivityCount: Int,
        val exportedServiceCount: Int,
        val exportedReceiverCount: Int,
        val exportedProviderCount: Int,
        val unprotectedExportedCount: Int,
        val hasSuspiciousNativeLibs: Boolean,
        val nativeLibCount: Int,
        /** Target SDK — lower = more attack surface */
        val targetSdk: Int,
        val minSdk: Int,
        /** APK size in bytes */
        val apkSizeBytes: Long
    )

    // ── Verdict summary (for quick queries) ──
    data class VerdictSummary(
        val effectiveRisk: TrustRiskModel.EffectiveRisk,
        val riskScore: Int,
        val hardFindingCount: Int,
        val softFindingCount: Int,
        val topReasons: List<String>
    )

    // ══════════════════════════════════════════════════════════
    //  Query helpers — used by RootCauseResolver and Sentinel
    // ══════════════════════════════════════════════════════════

    /** True if app has any ACTUALLY enabled dangerous special access */
    val hasActiveSpecialAccess: Boolean
        get() = specialAccess.hasAnySpecialAccess

    /** True if app has low trust AND active special access — high-priority target */
    val isHighPriorityTarget: Boolean
        get() = identity.trustScore < 40 && hasActiveSpecialAccess

    /** True if app had meaningful changes since last scan */
    val hasRecentChanges: Boolean
        get() = change.anomalies.isNotEmpty() || change.baselineStatus == BaselineManager.BaselineStatus.NEW

    /** True if app has capabilities + special access that together are suspicious */
    val hasSuspiciousProfile: Boolean
        get() = capability.unexpectedClusters.isNotEmpty() &&
                (hasActiveSpecialAccess || identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED)

    /** True if this app should be monitored by Sleeping Sentinel */
    val shouldMonitor: Boolean
        get() = isHighPriorityTarget || hasSuspiciousProfile ||
                verdict.effectiveRisk in setOf(
                    TrustRiskModel.EffectiveRisk.CRITICAL,
                    TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION
                )
}
