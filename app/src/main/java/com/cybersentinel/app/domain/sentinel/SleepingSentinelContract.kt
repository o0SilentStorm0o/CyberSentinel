package com.cybersentinel.app.domain.sentinel

import com.cybersentinel.app.domain.security.*

/**
 * Sleeping Sentinel Contract — interfaces and data classes ONLY.
 *
 * The Sleeping Sentinel is a background behavioral monitor that:
 *  1. Periodically samples device state (battery, network, CPU, wakeups)
 *  2. Builds a behavioral baseline per app
 *  3. Detects anomalies and correlates with App Scanner knowledge
 *  4. Emits SecuritySignals for the incident pipeline
 *
 * This file defines the CONTRACT — types, interfaces, enums.
 * Implementation will follow in Sprint 4.
 *
 * Architecture:
 *  SentinelWorker (WorkManager) → samples → SentinelAnalyzer → anomalies → SecuritySignals
 *  App Scanner (knowledge base) ← queries ← SentinelAnalyzer (context)
 */

// ══════════════════════════════════════════════════════════
//  Sampling — what the Sentinel collects
// ══════════════════════════════════════════════════════════

/**
 * A periodic sample of device and per-app state.
 * Collected by SentinelWorker every N minutes.
 */
data class SentinelSample(
    val timestamp: Long = System.currentTimeMillis(),
    val deviceState: DeviceStateSample,
    val appSamples: List<AppStateSample>
)

/**
 * Device-level state at sample time.
 */
data class DeviceStateSample(
    val batteryLevel: Int,          // 0-100
    val isCharging: Boolean,
    val screenOn: Boolean,
    val networkType: NetworkType,
    val vpnActive: Boolean,
    val totalRxBytes: Long,         // bytes received since boot
    val totalTxBytes: Long,         // bytes sent since boot
    val uptimeMillis: Long          // time since boot
)

enum class NetworkType {
    NONE, WIFI, MOBILE, VPN, OTHER
}

/**
 * Per-app state at sample time.
 * Only apps flagged by scanner (shouldMonitor=true) are sampled.
 */
data class AppStateSample(
    val packageName: String,
    val uid: Int,
    val rxBytes: Long,              // network bytes received
    val txBytes: Long,              // network bytes sent
    val foregroundServiceRunning: Boolean,
    val wakelockHeld: Boolean,
    val cpuTimeMs: Long,            // CPU time consumed
    val lastActivityTs: Long?       // last user-visible activity timestamp
)

// ══════════════════════════════════════════════════════════
//  Anomaly detection — what the Sentinel finds
// ══════════════════════════════════════════════════════════

/**
 * A behavioral anomaly detected by comparing samples against baseline.
 * Each anomaly type has specific detection criteria.
 */
sealed class BehaviorAnomaly {
    abstract val packageName: String
    abstract val detectedAt: Long
    abstract val confidence: Double    // 0.0–1.0
    abstract val description: String

    /**
     * Significant battery drain while the app has no visible UI.
     * Heuristic: battery dropped > X% per hour AND app was in background.
     */
    data class BatteryDrainWhileIdle(
        override val packageName: String,
        override val detectedAt: Long = System.currentTimeMillis(),
        override val confidence: Double,
        override val description: String = "Neobvyklé vybíjení baterie na pozadí",
        val drainPercentPerHour: Double,
        val wasForeground: Boolean = false
    ) : BehaviorAnomaly()

    /**
     * Network traffic burst at unusual times (e.g., 2-5 AM).
     * Heuristic: more than N KB in a window where baseline is near zero.
     */
    data class NetworkBurstAtNight(
        override val packageName: String,
        override val detectedAt: Long = System.currentTimeMillis(),
        override val confidence: Double,
        override val description: String = "Neobvyklý síťový provoz v nočních hodinách",
        val bytesTransferred: Long,
        val windowStart: Long,
        val windowEnd: Long
    ) : BehaviorAnomaly()

    /**
     * Excessive CPU wakeups / wakelock usage.
     * Heuristic: app held wakelock > X minutes in Y-minute window while screen off.
     */
    data class ExcessiveWakeupsPattern(
        override val packageName: String,
        override val detectedAt: Long = System.currentTimeMillis(),
        override val confidence: Double,
        override val description: String = "Nadměrné probouzení procesoru",
        val wakelockMinutes: Long,
        val windowMinutes: Long
    ) : BehaviorAnomaly()

    /**
     * App activity doesn't match expected context.
     * E.g., accessibility service active but user hasn't opened the app in days.
     */
    data class UnusualContext(
        override val packageName: String,
        override val detectedAt: Long = System.currentTimeMillis(),
        override val confidence: Double,
        override val description: String = "Aktivita neodpovídá kontextu",
        val contextDetail: String
    ) : BehaviorAnomaly()
}

// ══════════════════════════════════════════════════════════
//  Sentinel interfaces — contracts for future implementation
// ══════════════════════════════════════════════════════════

/**
 * The core analyzer that processes samples and detects anomalies.
 * Uses App Scanner knowledge for context-aware analysis.
 */
interface SentinelAnalyzer {
    /**
     * Process a new sample, compare with baseline, detect anomalies.
     * @param sample The current device/app state
     * @param appKnowledge Map of package → AppFeatureVector from scanner
     * @return List of detected anomalies (empty if everything normal)
     */
    fun analyze(
        sample: SentinelSample,
        appKnowledge: Map<String, AppFeatureVector>
    ): List<BehaviorAnomaly>

    /**
     * Convert behavioral anomalies to SecuritySignals for the incident pipeline.
     */
    fun toSignals(anomalies: List<BehaviorAnomaly>): List<SecuritySignal>

    /**
     * Get the set of packages that should be monitored.
     * Based on App Scanner verdicts: CRITICAL, NEEDS_ATTENTION, or hasActiveSpecialAccess.
     */
    fun getMonitoredPackages(appKnowledge: Map<String, AppFeatureVector>): Set<String>
}

/**
 * Manages the Sentinel behavioral baseline — what is "normal" for each app.
 */
interface SentinelBaselineManager {
    /**
     * Update baseline with new sample.
     * Uses exponential moving average to adapt to changing patterns.
     */
    fun updateBaseline(sample: SentinelSample)

    /**
     * Get the baseline for a specific app.
     * @return null if no baseline exists yet (need more samples)
     */
    fun getAppBaseline(packageName: String): AppBehaviorBaseline?

    /**
     * Check if we have enough samples to establish a reliable baseline.
     * Typically needs 3-7 days of samples.
     */
    fun isBaselineEstablished(packageName: String): Boolean
}

/**
 * Behavioral baseline for a single app — rolling averages of key metrics.
 */
data class AppBehaviorBaseline(
    val packageName: String,
    val sampleCount: Int,
    val firstSampleAt: Long,
    val lastSampleAt: Long,
    /** Average network bytes per hour */
    val avgNetworkBytesPerHour: Double,
    /** Average CPU time per hour (ms) */
    val avgCpuTimePerHour: Double,
    /** Average wakelock minutes per hour */
    val avgWakelockMinutesPerHour: Double,
    /** Hours when app is typically active (0-23) */
    val typicalActiveHours: Set<Int>,
    /** Standard deviation multiplier for anomaly threshold */
    val stdDevMultiplier: Double = 2.0
)
