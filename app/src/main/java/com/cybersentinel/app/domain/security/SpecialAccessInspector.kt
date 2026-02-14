package com.cybersentinel.app.domain.security

import android.annotation.SuppressLint
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.telecom.TelecomManager
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SpecialAccessInspector — checks the REAL enabled state of dangerous special access services.
 *
 * Key insight: A manifest declaration alone doesn't mean a service is active.
 * An app that declares BIND_ACCESSIBILITY_SERVICE but the user never enabled it
 * is NOT a threat. Only when the service is ACTUALLY running is it dangerous.
 *
 * Checks:
 *  1. Accessibility services — Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
 *  2. Notification listeners — Settings.Secure.ENABLED_NOTIFICATION_LISTENERS
 *  3. Device admins — DevicePolicyManager.getActiveAdmins()
 *  4. Default SMS app — TelecomManager / Telephony.Sms.getDefaultSmsPackage
 *  5. Default dialer — TelecomManager.getDefaultDialerPackage
 *  6. Draw over apps (overlay) — Settings.canDrawOverlays (per-app check)
 *  7. Battery optimization ignored — PowerManager.isIgnoringBatteryOptimizations
 *
 * Output: SpecialAccessSnapshot per app — used by TrustRiskModel to gate cluster activation.
 */
@Singleton
class SpecialAccessInspector @Inject constructor(
    @ApplicationContext private val context: Context
) {

    // ══════════════════════════════════════════════════════════
    //  Data model
    // ══════════════════════════════════════════════════════════

    /**
     * Per-app snapshot of special access enabled states.
     * Only flags that are TRUE represent real active threats.
     */
    data class SpecialAccessSnapshot(
        val packageName: String,
        /** Accessibility service is actively enabled by user */
        val accessibilityEnabled: Boolean = false,
        /** Notification listener is actively enabled by user */
        val notificationListenerEnabled: Boolean = false,
        /** App is an active device administrator */
        val deviceAdminEnabled: Boolean = false,
        /** App is the default SMS handler */
        val isDefaultSms: Boolean = false,
        /** App is the default dialer */
        val isDefaultDialer: Boolean = false,
        /** App can draw overlays (SYSTEM_ALERT_WINDOW granted) */
        val overlayEnabled: Boolean = false,
        /** App is exempt from battery optimization (Doze) */
        val batteryOptimizationIgnored: Boolean = false
    ) {
        /** True if any special access is actually enabled */
        val hasAnySpecialAccess: Boolean
            get() = accessibilityEnabled || notificationListenerEnabled ||
                    deviceAdminEnabled || isDefaultSms || isDefaultDialer ||
                    overlayEnabled || batteryOptimizationIgnored

        /** Count of active special access types */
        val activeCount: Int
            get() = listOf(
                accessibilityEnabled, notificationListenerEnabled,
                deviceAdminEnabled, isDefaultSms, isDefaultDialer,
                overlayEnabled, batteryOptimizationIgnored
            ).count { it }

        /** Active special access types as human-readable labels */
        val activeLabels: List<String>
            get() = buildList {
                if (accessibilityEnabled) add("Usnadnění přístupu")
                if (notificationListenerEnabled) add("Čtení notifikací")
                if (deviceAdminEnabled) add("Správce zařízení")
                if (isDefaultSms) add("Výchozí SMS")
                if (isDefaultDialer) add("Výchozí telefon")
                if (overlayEnabled) add("Překrytí obrazovky")
                if (batteryOptimizationIgnored) add("Bez optimalizace baterie")
            }
    }

    // ══════════════════════════════════════════════════════════
    //  System-wide queries (cached per scan cycle)
    // ══════════════════════════════════════════════════════════

    /** Parse colon-and-slash separated component list from Settings.Secure */
    private fun parseEnabledServices(settingKey: String): Set<String> {
        val raw = Settings.Secure.getString(context.contentResolver, settingKey)
            ?: return emptySet()
        return raw.split(":")
            .filter { it.isNotBlank() }
            .mapNotNull { componentStr ->
                try {
                    ComponentName.unflattenFromString(componentStr)?.packageName
                } catch (_: Exception) {
                    // Malformed entry, skip
                    null
                }
            }
            .toSet()
    }

    /** Get all packages with enabled accessibility services */
    fun getEnabledAccessibilityPackages(): Set<String> =
        parseEnabledServices(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)

    /** Get all packages with enabled notification listeners */
    fun getEnabledNotificationListenerPackages(): Set<String> =
        parseEnabledServices("enabled_notification_listeners")

    /** Get all packages that are active device administrators */
    fun getActiveDeviceAdminPackages(): Set<String> {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return emptySet()
        return dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()
    }

    /** Get the default SMS handler package */
    @SuppressLint("QueryPermissionsNeeded")
    fun getDefaultSmsPackage(): String? {
        return try {
            android.provider.Telephony.Sms.getDefaultSmsPackage(context)
        } catch (_: Exception) {
            null
        }
    }

    /** Get the default dialer package */
    @SuppressLint("QueryPermissionsNeeded")
    fun getDefaultDialerPackage(): String? {
        return try {
            val telecom = context.getSystemService(Context.TELECOM_SERVICE) as? TelecomManager
            telecom?.defaultDialerPackage
        } catch (_: Exception) {
            null
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Per-app inspection
    // ══════════════════════════════════════════════════════════

    /**
     * Check special access for a single app.
     * Call this with pre-computed system-wide sets for efficiency.
     */
    fun inspectApp(
        packageName: String,
        enabledAccessibility: Set<String> = getEnabledAccessibilityPackages(),
        enabledNotifListeners: Set<String> = getEnabledNotificationListenerPackages(),
        activeAdmins: Set<String> = getActiveDeviceAdminPackages(),
        defaultSms: String? = getDefaultSmsPackage(),
        defaultDialer: String? = getDefaultDialerPackage()
    ): SpecialAccessSnapshot {
        return SpecialAccessSnapshot(
            packageName = packageName,
            accessibilityEnabled = packageName in enabledAccessibility,
            notificationListenerEnabled = packageName in enabledNotifListeners,
            deviceAdminEnabled = packageName in activeAdmins,
            isDefaultSms = packageName == defaultSms,
            isDefaultDialer = packageName == defaultDialer,
            overlayEnabled = checkOverlayPermission(packageName),
            batteryOptimizationIgnored = checkBatteryOptIgnored(packageName)
        )
    }

    /**
     * Batch inspect all packages — efficient: queries system state once,
     * then checks each package against cached sets.
     */
    fun inspectAll(packageNames: List<String>): Map<String, SpecialAccessSnapshot> {
        // Query system state once
        val enabledA11y = getEnabledAccessibilityPackages()
        val enabledNotif = getEnabledNotificationListenerPackages()
        val activeAdmins = getActiveDeviceAdminPackages()
        val defaultSms = getDefaultSmsPackage()
        val defaultDialer = getDefaultDialerPackage()

        return packageNames.associateWith { pkg ->
            inspectApp(
                packageName = pkg,
                enabledAccessibility = enabledA11y,
                enabledNotifListeners = enabledNotif,
                activeAdmins = activeAdmins,
                defaultSms = defaultSms,
                defaultDialer = defaultDialer
            )
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Per-app checks (require individual API calls)
    // ══════════════════════════════════════════════════════════

    /**
     * Check if an app has SYSTEM_ALERT_WINDOW (overlay) permission granted.
     * On API 23+, this requires explicit user grant via Settings.ACTION_MANAGE_OVERLAY_PERMISSION.
     */
    private fun checkOverlayPermission(packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                // Check via AppOpsManager for specific package
                val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
                val uid = context.packageManager.getApplicationInfo(packageName, 0).uid
                @Suppress("DEPRECATION")
                val mode = appOps.checkOpNoThrow(
                    android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                    uid,
                    packageName
                )
                mode == android.app.AppOpsManager.MODE_ALLOWED
            } else {
                // Pre-M: permission granted at install time
                context.packageManager.checkPermission(
                    android.Manifest.permission.SYSTEM_ALERT_WINDOW,
                    packageName
                ) == android.content.pm.PackageManager.PERMISSION_GRANTED
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if an app is exempt from battery optimization (Doze whitelist).
     * Apps on this list can wake CPU, use network, and run background services freely.
     */
    private fun checkBatteryOptIgnored(packageName: String): Boolean {
        return try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            pm?.isIgnoringBatteryOptimizations(packageName) ?: false
        } catch (_: Exception) {
            false
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Summary for device-wide reporting
    // ══════════════════════════════════════════════════════════

    /**
     * Device-wide special access summary — how many apps have each type enabled.
     */
    data class DeviceSpecialAccessSummary(
        val accessibilityServices: Set<String>,
        val notificationListeners: Set<String>,
        val deviceAdmins: Set<String>,
        val defaultSms: String?,
        val defaultDialer: String?,
        val totalAppsWithSpecialAccess: Int
    )

    fun getDeviceSummary(): DeviceSpecialAccessSummary {
        val a11y = getEnabledAccessibilityPackages()
        val notif = getEnabledNotificationListenerPackages()
        val admins = getActiveDeviceAdminPackages()
        val allPkgs = (a11y + notif + admins).toSet()

        return DeviceSpecialAccessSummary(
            accessibilityServices = a11y,
            notificationListeners = notif,
            deviceAdmins = admins,
            defaultSms = getDefaultSmsPackage(),
            defaultDialer = getDefaultDialerPackage(),
            totalAppsWithSpecialAccess = allPkgs.size
        )
    }
}
