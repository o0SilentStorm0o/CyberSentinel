package com.cybersentinel.app.domain.capability

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.os.StatFs
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * DeviceCapabilityProfile — static and runtime hardware characteristics.
 *
 * Two-stage profiling (colleague's design):
 *  1. Static tier: RAM, ABI, storage, OS version → computed once at startup
 *  2. Runtime snapshot: available RAM, power saver, thermal status → checked before each LLM call
 *
 * Used by FeatureGatekeeper to decide which ExplanationEngine to use.
 */

// ══════════════════════════════════════════════════════════
//  Data models
// ══════════════════════════════════════════════════════════

/**
 * Static device profile — computed once, doesn't change during app lifetime.
 */
data class StaticDeviceProfile(
    /** Total RAM in MB */
    val totalRamMb: Long,
    /** Primary CPU ABI (e.g., "arm64-v8a", "armeabi-v7a", "x86_64") */
    val primaryAbi: String,
    /** All supported ABIs */
    val supportedAbis: List<String>,
    /** True if device supports 64-bit */
    val is64Bit: Boolean,
    /** Android SDK version (e.g., 26, 33, 35) */
    val sdkVersion: Int,
    /** Total internal storage in MB */
    val totalStorageMb: Long,
    /** Available internal storage in MB (at profiling time) */
    val availableStorageMb: Long,
    /** Number of CPU cores */
    val cpuCoreCount: Int,
    /** Device manufacturer */
    val manufacturer: String,
    /** Device model */
    val model: String
) {
    /** Human-readable summary for logging */
    val summary: String
        get() = "$manufacturer $model | ${totalRamMb}MB RAM | $primaryAbi | " +
            "SDK $sdkVersion | ${cpuCoreCount} cores | ${availableStorageMb}MB free"
}

/**
 * Runtime device snapshot — checked before each LLM inference decision.
 *
 * These values change constantly, so we capture them on demand.
 */
data class RuntimeDeviceSnapshot(
    /** Available RAM in MB right now */
    val availableRamMb: Long,
    /** True if device is in power saver / battery saver mode */
    val isPowerSaverActive: Boolean,
    /** True if device is experiencing thermal throttling (API 29+) */
    val isThermalThrottling: Boolean,
    /** True if the app is currently in background */
    val isInBackground: Boolean,
    /** Timestamp of this snapshot */
    val timestamp: Long = System.currentTimeMillis()
)

// ══════════════════════════════════════════════════════════
//  DeviceProfiler — produces profiles from system APIs
// ══════════════════════════════════════════════════════════

/**
 * DeviceProfiler — reads hardware capabilities from Android system APIs.
 *
 * Thread safety: All reads are from system services, safe for any thread.
 * No disk I/O, no network, no blocking.
 */
@Singleton
class DeviceProfiler @Inject constructor(
    @ApplicationContext private val context: Context
) {

    /** Cached static profile — computed once on first access */
    @Volatile
    private var cachedStaticProfile: StaticDeviceProfile? = null

    /**
     * Get the static device profile. Computed once and cached.
     */
    fun getStaticProfile(): StaticDeviceProfile {
        cachedStaticProfile?.let { return it }
        return computeStaticProfile().also { cachedStaticProfile = it }
    }

    /**
     * Get a fresh runtime snapshot. Always recomputed.
     */
    fun getRuntimeSnapshot(isInBackground: Boolean = false): RuntimeDeviceSnapshot {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memInfo)

        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager

        val isThermal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // API 29+: Check thermal status
            // THERMAL_STATUS_MODERATE (2) or higher = throttling
            try {
                val thermalStatus = powerManager.currentThermalStatus
                thermalStatus >= PowerManager.THERMAL_STATUS_MODERATE
            } catch (_: Exception) {
                false
            }
        } else {
            false
        }

        return RuntimeDeviceSnapshot(
            availableRamMb = memInfo.availMem / (1024 * 1024),
            isPowerSaverActive = powerManager.isPowerSaveMode,
            isThermalThrottling = isThermal,
            isInBackground = isInBackground
        )
    }

    // ── Private implementation ──

    private fun computeStaticProfile(): StaticDeviceProfile {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memInfo)

        val supportedAbis = Build.SUPPORTED_ABIS.toList()
        val primaryAbi = supportedAbis.firstOrNull() ?: "unknown"

        val stat = StatFs(Environment.getDataDirectory().path)
        val totalStorage = stat.totalBytes / (1024 * 1024)
        val availableStorage = stat.availableBytes / (1024 * 1024)

        return StaticDeviceProfile(
            totalRamMb = memInfo.totalMem / (1024 * 1024),
            primaryAbi = primaryAbi,
            supportedAbis = supportedAbis,
            is64Bit = primaryAbi.contains("64"),
            sdkVersion = Build.VERSION.SDK_INT,
            totalStorageMb = totalStorage,
            availableStorageMb = availableStorage,
            cpuCoreCount = Runtime.getRuntime().availableProcessors(),
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL
        )
    }
}
