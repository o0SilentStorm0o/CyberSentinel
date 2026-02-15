package com.cybersentinel.app.domain.security

/**
 * InstallTimelineAnalyzer — temporal correlation engine for dropper/loader detection.
 *
 * Core insight: Legitimate apps request permissions at install time.
 * Dropper/loader apps install quietly, then escalate over time:
 *
 *   T0:          Install (benign-looking, few permissions)
 *   T0 + min:    SMS read/send (C2 channel)
 *   T0 + hours:  Accessibility + Overlay (banking attack surface)
 *   T0 + days:   BOOT_COMPLETED + foreground service (persistence)
 *
 * This analyzer tracks these transitions and produces a **DropperTimelineScore**
 * that feeds into RootCauseResolver for hypothesis confidence boosting.
 *
 * Design:
 *  - Pure, deterministic, no side effects
 *  - Operates on AppFeatureVector + list of SecurityEvents
 *  - Thread-safe (stateless)
 *
 * Time windows (configurable):
 *  - IMMEDIATE:  0–10 min after install → SMS/network = suspicious
 *  - SHORT:      10 min–6 hours → accessibility/overlay = very suspicious
 *  - MEDIUM:     6–48 hours → permission escalation = suspicious
 *  - LONG:       >48 hours → persistence mechanisms = mild signal
 */
class InstallTimelineAnalyzer {

    // ══════════════════════════════════════════════════════════
    //  Time window definitions (milliseconds)
    // ══════════════════════════════════════════════════════════

    companion object {
        /** 0–10 minutes after install */
        const val IMMEDIATE_WINDOW_MS = 10L * 60 * 1000

        /** 10 min – 6 hours after install */
        const val SHORT_WINDOW_MS = 6L * 60 * 60 * 1000

        /** 6 – 48 hours after install */
        const val MEDIUM_WINDOW_MS = 48L * 60 * 60 * 1000

        /** Minimum freshness: app installed less than 48h ago to count as "fresh" */
        const val FRESH_INSTALL_THRESHOLD_MS = 48L * 60 * 60 * 1000

        /** Weights for timeline score components */
        const val WEIGHT_IMMEDIATE_NETWORK = 0.15
        const val WEIGHT_IMMEDIATE_SMS = 0.20
        const val WEIGHT_SHORT_ACCESSIBILITY = 0.25
        const val WEIGHT_SHORT_OVERLAY = 0.20
        const val WEIGHT_MEDIUM_PERMISSION_ESCALATION = 0.15
        const val WEIGHT_BOOT_PERSISTENCE = 0.10
        const val WEIGHT_FRESH_INSTALL_BASE = 0.10
        const val WEIGHT_LOW_TRUST_BOOST = 0.15
        const val WEIGHT_SIDELOAD_BOOST = 0.10
    }

    // ══════════════════════════════════════════════════════════
    //  Output model
    // ══════════════════════════════════════════════════════════

    /**
     * Timeline analysis result for a single app.
     *
     * @param packageName The analyzed app's package
     * @param score 0.0–1.0, higher = more dropper-like timeline pattern
     * @param phase Which timeline phase the app is currently in
     * @param signals Specific timeline signals that contributed to the score
     * @param installAge How long ago the app was installed (ms), null if unknown
     * @param isFreshInstall True if app was installed within FRESH_INSTALL_THRESHOLD_MS
     */
    data class TimelineResult(
        val packageName: String,
        val score: Double,
        val phase: TimelinePhase,
        val signals: List<TimelineSignal>,
        val installAge: Long?,
        val isFreshInstall: Boolean
    ) {
        /** True if this timeline pattern warrants dropper hypothesis boosting */
        val isDropperCandidate: Boolean
            get() = score >= 0.30

        /** True if this is a high-confidence dropper timeline */
        val isHighConfidenceDropper: Boolean
            get() = score >= 0.55
    }

    /**
     * Which phase of the dropper timeline the app is in.
     */
    enum class TimelinePhase {
        /** Not a fresh install or no timeline data */
        NOT_APPLICABLE,
        /** T0–10min: Just installed, watching for C2 setup */
        IMMEDIATE,
        /** T0+10min–6h: Watching for capability acquisition */
        SHORT_TERM,
        /** T0+6h–48h: Watching for permission escalation */
        MEDIUM_TERM,
        /** T0+48h+: Past fresh window, reduced suspicion */
        ESTABLISHED
    }

    /**
     * Individual timeline signal — a specific suspicious timing pattern detected.
     */
    data class TimelineSignal(
        val type: TimelineSignalType,
        val description: String,
        val weight: Double,
        val timeAfterInstallMs: Long?
    )

    enum class TimelineSignalType {
        /** Network burst in IMMEDIATE window → C2 phone-home / payload fetch */
        IMMEDIATE_NETWORK_BURST,
        /** SMS access in IMMEDIATE window → C2 via SMS */
        IMMEDIATE_SMS_ACCESS,
        /** Accessibility requested in SHORT window → UI hijack setup */
        SHORT_TERM_ACCESSIBILITY,
        /** Overlay requested in SHORT window → phishing setup */
        SHORT_TERM_OVERLAY,
        /** Permission escalation in MEDIUM window → staged capability buildup */
        MEDIUM_TERM_ESCALATION,
        /** BOOT_COMPLETED receiver → persistence mechanism */
        BOOT_PERSISTENCE,
        /** App is a fresh install (base signal) */
        FRESH_INSTALL,
        /** Low trust app → amplifies all signals */
        LOW_TRUST_AMPLIFIER,
        /** Sideloaded app → amplifies all signals */
        SIDELOAD_AMPLIFIER,
        /** Dynamic code loading detected → loader behavior */
        DYNAMIC_CODE_LOADING,
        /** Install packages permission on fresh app → dropper intent */
        FRESH_INSTALL_WITH_INSTALLER_PERM
    }

    // ══════════════════════════════════════════════════════════
    //  Core analysis
    // ══════════════════════════════════════════════════════════

    /**
     * Analyze a single app's timeline for dropper/loader patterns.
     *
     * @param app The app's feature vector (contains install time, trust, permissions)
     * @param recentEvents Recent security events for this app (last 48h)
     * @param now Current timestamp (injectable for testing)
     * @return TimelineResult with score and detected signals
     */
    fun analyze(
        app: AppFeatureVector,
        recentEvents: List<SecurityEvent>,
        now: Long = System.currentTimeMillis()
    ): TimelineResult {
        val signals = mutableListOf<TimelineSignal>()

        // ── Determine install age ──
        val installTime = app.change.lastUpdateAt ?: app.timestamp
        val installAge = now - installTime
        val isFreshInstall = installAge in 1..FRESH_INSTALL_THRESHOLD_MS

        val phase = when {
            !isFreshInstall -> TimelinePhase.ESTABLISHED
            installAge <= IMMEDIATE_WINDOW_MS -> TimelinePhase.IMMEDIATE
            installAge <= SHORT_WINDOW_MS -> TimelinePhase.SHORT_TERM
            installAge <= MEDIUM_WINDOW_MS -> TimelinePhase.MEDIUM_TERM
            else -> TimelinePhase.NOT_APPLICABLE
        }

        // If not a fresh install, limited analysis
        if (!isFreshInstall) {
            return TimelineResult(
                packageName = app.packageName,
                score = 0.0,
                phase = phase,
                signals = emptyList(),
                installAge = installAge,
                isFreshInstall = false
            )
        }

        // ── Base signal: fresh install ──
        signals.add(
            TimelineSignal(
                type = TimelineSignalType.FRESH_INSTALL,
                description = "Aplikace nainstalována před ${formatAge(installAge)}",
                weight = WEIGHT_FRESH_INSTALL_BASE,
                timeAfterInstallMs = installAge
            )
        )

        // ── Check event signals relative to install time ──
        val appEvents = recentEvents.filter { it.packageName == app.packageName }
        val signalTypes = appEvents.flatMap { e -> e.signals.map { it.type } }.toSet()
        val eventTypes = appEvents.map { it.type }.toSet()

        // IMMEDIATE window signals
        if (installAge <= IMMEDIATE_WINDOW_MS || hasEventInWindow(appEvents, installTime, IMMEDIATE_WINDOW_MS)) {
            if (SignalType.NETWORK_BURST_ANOMALY in signalTypes ||
                SignalType.NETWORK_AFTER_INSTALL in signalTypes
            ) {
                signals.add(
                    TimelineSignal(
                        type = TimelineSignalType.IMMEDIATE_NETWORK_BURST,
                        description = "Síťový provoz ihned po instalaci",
                        weight = WEIGHT_IMMEDIATE_NETWORK,
                        timeAfterInstallMs = installAge
                    )
                )
            }
            if (hasSmsCapability(app)) {
                signals.add(
                    TimelineSignal(
                        type = TimelineSignalType.IMMEDIATE_SMS_ACCESS,
                        description = "SMS přístup vyžádán ihned po instalaci",
                        weight = WEIGHT_IMMEDIATE_SMS,
                        timeAfterInstallMs = installAge
                    )
                )
            }
        }

        // SHORT window signals (accessibility, overlay)
        if (installAge <= SHORT_WINDOW_MS || hasEventInWindow(appEvents, installTime, SHORT_WINDOW_MS)) {
            if (hasAccessibility(app) || SignalType.SPECIAL_ACCESS_ENABLED in signalTypes ||
                SignalType.UNKNOWN_ACCESSIBILITY_SERVICE in signalTypes
            ) {
                signals.add(
                    TimelineSignal(
                        type = TimelineSignalType.SHORT_TERM_ACCESSIBILITY,
                        description = "Přístupnost aktivována do ${formatAge(SHORT_WINDOW_MS)} od instalace",
                        weight = WEIGHT_SHORT_ACCESSIBILITY,
                        timeAfterInstallMs = installAge
                    )
                )
            }
            if (hasOverlay(app)) {
                signals.add(
                    TimelineSignal(
                        type = TimelineSignalType.SHORT_TERM_OVERLAY,
                        description = "Overlay oprávnění do ${formatAge(SHORT_WINDOW_MS)} od instalace",
                        weight = WEIGHT_SHORT_OVERLAY,
                        timeAfterInstallMs = installAge
                    )
                )
            }
        }

        // MEDIUM window signals (permission escalation)
        if (installAge <= MEDIUM_WINDOW_MS) {
            if (SignalType.HIGH_RISK_PERM_ADDED in signalTypes ||
                SignalType.POST_INSTALL_PERMISSION_ESCALATION in signalTypes
            ) {
                signals.add(
                    TimelineSignal(
                        type = TimelineSignalType.MEDIUM_TERM_ESCALATION,
                        description = "Eskalace oprávnění do ${formatAge(MEDIUM_WINDOW_MS)} od instalace",
                        weight = WEIGHT_MEDIUM_PERMISSION_ESCALATION,
                        timeAfterInstallMs = installAge
                    )
                )
            }
        }

        // ── Non-time-bound signals that amplify the timeline ──

        // Boot persistence
        if (SignalType.BOOT_PERSISTENCE in signalTypes || hasBootReceiver(app)) {
            signals.add(
                TimelineSignal(
                    type = TimelineSignalType.BOOT_PERSISTENCE,
                    description = "Registrován BOOT_COMPLETED receiver",
                    weight = WEIGHT_BOOT_PERSISTENCE,
                    timeAfterInstallMs = null
                )
            )
        }

        // Dynamic code loading
        if (SignalType.DYNAMIC_CODE_LOADING in signalTypes) {
            signals.add(
                TimelineSignal(
                    type = TimelineSignalType.DYNAMIC_CODE_LOADING,
                    description = "Detekováno dynamické načítání kódu",
                    weight = 0.15,
                    timeAfterInstallMs = null
                )
            )
        }

        // Fresh install with INSTALL_PACKAGES permission
        if (hasInstallPackages(app)) {
            signals.add(
                TimelineSignal(
                    type = TimelineSignalType.FRESH_INSTALL_WITH_INSTALLER_PERM,
                    description = "Čerstvě instalovaná aplikace s oprávněním instalovat další aplikace",
                    weight = 0.15,
                    timeAfterInstallMs = installAge
                )
            )
        }

        // ── Trust/sideload amplifiers ──
        if (app.identity.trustLevel == TrustEvidenceEngine.TrustLevel.LOW ||
            app.identity.trustLevel == TrustEvidenceEngine.TrustLevel.ANOMALOUS
        ) {
            signals.add(
                TimelineSignal(
                    type = TimelineSignalType.LOW_TRUST_AMPLIFIER,
                    description = "Nízká důvěra aplikace (${app.identity.trustScore})",
                    weight = WEIGHT_LOW_TRUST_BOOST,
                    timeAfterInstallMs = null
                )
            )
        }

        if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
            signals.add(
                TimelineSignal(
                    type = TimelineSignalType.SIDELOAD_AMPLIFIER,
                    description = "Aplikace instalována mimo obchod (sideload)",
                    weight = WEIGHT_SIDELOAD_BOOST,
                    timeAfterInstallMs = null
                )
            )
        }

        // ── Compute score ──
        val rawScore = signals.sumOf { it.weight }
        val finalScore = rawScore.coerceIn(0.0, 1.0)

        return TimelineResult(
            packageName = app.packageName,
            score = finalScore,
            phase = phase,
            signals = signals,
            installAge = installAge,
            isFreshInstall = true
        )
    }

    /**
     * Batch-analyze multiple apps and return those with dropper-like timelines.
     *
     * @return Sorted descending by score; only includes apps with score > 0
     */
    fun analyzeAll(
        apps: List<AppFeatureVector>,
        recentEvents: List<SecurityEvent>,
        now: Long = System.currentTimeMillis()
    ): List<TimelineResult> {
        return apps
            .map { app ->
                val appEvents = recentEvents.filter { it.packageName == app.packageName }
                analyze(app, appEvents, now)
            }
            .filter { it.score > 0.0 }
            .sortedByDescending { it.score }
    }

    // ══════════════════════════════════════════════════════════
    //  Capability checks
    // ══════════════════════════════════════════════════════════

    private fun hasSmsCapability(app: AppFeatureVector): Boolean =
        app.capability.activeHighRiskClusters.any {
            it == TrustRiskModel.CapabilityCluster.SMS
        }

    private fun hasAccessibility(app: AppFeatureVector): Boolean =
        app.capability.activeHighRiskClusters.any {
            it == TrustRiskModel.CapabilityCluster.ACCESSIBILITY
        } || app.specialAccess.accessibilityEnabled

    private fun hasOverlay(app: AppFeatureVector): Boolean =
        app.capability.activeHighRiskClusters.any {
            it == TrustRiskModel.CapabilityCluster.OVERLAY
        }

    private fun hasInstallPackages(app: AppFeatureVector): Boolean =
        app.capability.activeHighRiskClusters.any {
            it == TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES
        }

    private fun hasBootReceiver(app: AppFeatureVector): Boolean =
        // Approximate: high exported receiver count on fresh install = persistence
        app.surface.exportedReceiverCount > 0 && app.identity.isNewApp

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun hasEventInWindow(
        events: List<SecurityEvent>,
        installTime: Long,
        windowMs: Long
    ): Boolean {
        return events.any { event ->
            val eventAge = event.startTime - installTime
            eventAge in 0..windowMs
        }
    }

    /**
     * Human-readable age string (Czech).
     */
    internal fun formatAge(ageMs: Long): String = when {
        ageMs < 60_000 -> "${ageMs / 1000} s"
        ageMs < 3_600_000 -> "${ageMs / 60_000} min"
        ageMs < 86_400_000 -> "${ageMs / 3_600_000} h"
        else -> "${ageMs / 86_400_000} d"
    }
}
