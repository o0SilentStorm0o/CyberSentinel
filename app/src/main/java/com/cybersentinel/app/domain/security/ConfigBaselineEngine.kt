package com.cybersentinel.app.domain.security

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.security.KeyChain
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ConfigBaselineEngine — monitors "hidden places" that attackers can abuse.
 *
 * Checks:
 *  1. User-installed CA certificates — MITM proxy / corporate intercept
 *  2. Private DNS setting — DNS-based filtering / redirection
 *  3. Active VPN — traffic interception
 *  4. Wi-Fi proxy — HTTP(S) interception
 *  5. Enabled accessibility services — system-wide keylogging / screen reading
 *  6. Enabled notification listeners — message interception
 *  7. Default apps — default SMS / dialer / browser replacement
 *
 * Output: ConfigSnapshot — compared between scans to detect changes.
 * Changes generate SecuritySignals for the incident pipeline.
 */
@Singleton
class ConfigBaselineEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val specialAccessInspector: SpecialAccessInspector
) {

    // ══════════════════════════════════════════════════════════
    //  Data model
    // ══════════════════════════════════════════════════════════

    /**
     * Snapshot of device configuration at scan time.
     * Pure data — no logic, no side effects.
     */
    data class ConfigSnapshot(
        val timestamp: Long = System.currentTimeMillis(),

        // ── CA Certificates ──
        /** SHA-256 fingerprints of user-installed CA certs */
        val userCaCertFingerprints: Set<String> = emptySet(),
        /** Number of user-installed CA certs */
        val userCaCertCount: Int = 0,

        // ── DNS ──
        /** Private DNS mode: off / opportunistic / hostname / unknown */
        val privateDnsMode: String? = null,
        /** Private DNS hostname (if mode = hostname) */
        val privateDnsHostname: String? = null,

        // ── VPN ──
        /** True if a VPN is currently active */
        val vpnActive: Boolean = false,

        // ── Proxy ──
        /** True if a global HTTP proxy is configured */
        val globalProxyConfigured: Boolean = false,
        /** Proxy host (if configured) */
        val proxyHost: String? = null,

        // ── Accessibility services ──
        /** Packages with enabled accessibility services */
        val enabledAccessibilityServices: Set<String> = emptySet(),

        // ── Notification listeners ──
        /** Packages with enabled notification listeners */
        val enabledNotificationListeners: Set<String> = emptySet(),

        // ── Default apps ──
        val defaultSmsApp: String? = null,
        val defaultDialerApp: String? = null,

        // ── Developer options ──
        val developerOptionsEnabled: Boolean = false,
        val usbDebuggingEnabled: Boolean = false,
        val installFromUnknownSourcesEnabled: Boolean = false
    ) {
        /** Hash of the entire config for quick change detection */
        val configHash: String
            get() {
                val content = buildString {
                    append("ca:${userCaCertFingerprints.sorted().joinToString(",")}")
                    append("|dns:$privateDnsMode:$privateDnsHostname")
                    append("|vpn:$vpnActive")
                    append("|proxy:$globalProxyConfigured:$proxyHost")
                    append("|a11y:${enabledAccessibilityServices.sorted().joinToString(",")}")
                    append("|notif:${enabledNotificationListeners.sorted().joinToString(",")}")
                    append("|sms:$defaultSmsApp|dialer:$defaultDialerApp")
                    append("|dev:$developerOptionsEnabled|usb:$usbDebuggingEnabled")
                }
                val digest = MessageDigest.getInstance("SHA-256")
                return digest.digest(content.toByteArray()).joinToString("") { "%02x".format(it) }
            }
    }

    /**
     * Changes detected between two config snapshots.
     */
    data class ConfigDelta(
        val hasChanges: Boolean,
        val changes: List<ConfigChange>
    )

    data class ConfigChange(
        val type: ConfigChangeType,
        val severity: SignalSeverity,
        val description: String,
        val oldValue: String? = null,
        val newValue: String? = null
    )

    enum class ConfigChangeType {
        CA_CERT_ADDED,
        CA_CERT_REMOVED,
        PRIVATE_DNS_CHANGED,
        VPN_ACTIVATED,
        VPN_DEACTIVATED,
        PROXY_CONFIGURED,
        PROXY_REMOVED,
        ACCESSIBILITY_SERVICE_ADDED,
        ACCESSIBILITY_SERVICE_REMOVED,
        NOTIFICATION_LISTENER_ADDED,
        NOTIFICATION_LISTENER_REMOVED,
        DEFAULT_SMS_CHANGED,
        DEFAULT_DIALER_CHANGED,
        DEVELOPER_OPTIONS_CHANGED,
        USB_DEBUGGING_CHANGED,
        UNKNOWN_SOURCES_CHANGED
    }

    // ══════════════════════════════════════════════════════════
    //  Snapshot capture
    // ══════════════════════════════════════════════════════════

    /**
     * Take a snapshot of current device configuration.
     */
    @SuppressLint("HardwareIds")
    fun captureSnapshot(): ConfigSnapshot {
        return ConfigSnapshot(
            timestamp = System.currentTimeMillis(),
            userCaCertFingerprints = getUserCaCertFingerprints(),
            userCaCertCount = getUserCaCertFingerprints().size,
            privateDnsMode = getPrivateDnsMode(),
            privateDnsHostname = getPrivateDnsHostname(),
            vpnActive = isVpnActive(),
            globalProxyConfigured = isGlobalProxyConfigured(),
            proxyHost = getProxyHost(),
            enabledAccessibilityServices = specialAccessInspector.getEnabledAccessibilityPackages(),
            enabledNotificationListeners = specialAccessInspector.getEnabledNotificationListenerPackages(),
            defaultSmsApp = specialAccessInspector.getDefaultSmsPackage(),
            defaultDialerApp = specialAccessInspector.getDefaultDialerPackage(),
            developerOptionsEnabled = isDeveloperOptionsEnabled(),
            usbDebuggingEnabled = isUsbDebuggingEnabled(),
            installFromUnknownSourcesEnabled = isUnknownSourcesEnabled()
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Delta detection
    // ══════════════════════════════════════════════════════════

    /**
     * Compare two snapshots and return a list of changes.
     */
    fun compareSnapshots(old: ConfigSnapshot, new: ConfigSnapshot): ConfigDelta {
        val changes = mutableListOf<ConfigChange>()

        // CA cert changes
        val addedCerts = new.userCaCertFingerprints - old.userCaCertFingerprints
        val removedCerts = old.userCaCertFingerprints - new.userCaCertFingerprints
        for (cert in addedCerts) {
            changes.add(ConfigChange(
                type = ConfigChangeType.CA_CERT_ADDED,
                severity = SignalSeverity.HIGH,
                description = "Přidán uživatelský CA certifikát",
                newValue = cert.take(16) + "..."
            ))
        }
        for (cert in removedCerts) {
            changes.add(ConfigChange(
                type = ConfigChangeType.CA_CERT_REMOVED,
                severity = SignalSeverity.MEDIUM,
                description = "Odebrán uživatelský CA certifikát",
                oldValue = cert.take(16) + "..."
            ))
        }

        // DNS changes
        if (old.privateDnsMode != new.privateDnsMode || old.privateDnsHostname != new.privateDnsHostname) {
            changes.add(ConfigChange(
                type = ConfigChangeType.PRIVATE_DNS_CHANGED,
                severity = SignalSeverity.MEDIUM,
                description = "Změna nastavení privátního DNS",
                oldValue = "${old.privateDnsMode}:${old.privateDnsHostname}",
                newValue = "${new.privateDnsMode}:${new.privateDnsHostname}"
            ))
        }

        // VPN changes
        if (!old.vpnActive && new.vpnActive) {
            changes.add(ConfigChange(
                type = ConfigChangeType.VPN_ACTIVATED,
                severity = SignalSeverity.MEDIUM,
                description = "VPN aktivována"
            ))
        } else if (old.vpnActive && !new.vpnActive) {
            changes.add(ConfigChange(
                type = ConfigChangeType.VPN_DEACTIVATED,
                severity = SignalSeverity.LOW,
                description = "VPN deaktivována"
            ))
        }

        // Proxy changes
        if (!old.globalProxyConfigured && new.globalProxyConfigured) {
            changes.add(ConfigChange(
                type = ConfigChangeType.PROXY_CONFIGURED,
                severity = SignalSeverity.HIGH,
                description = "Globální proxy nakonfigurována",
                newValue = new.proxyHost
            ))
        } else if (old.globalProxyConfigured && !new.globalProxyConfigured) {
            changes.add(ConfigChange(
                type = ConfigChangeType.PROXY_REMOVED,
                severity = SignalSeverity.LOW,
                description = "Globální proxy odebrána"
            ))
        }

        // Accessibility service changes
        val addedA11y = new.enabledAccessibilityServices - old.enabledAccessibilityServices
        val removedA11y = old.enabledAccessibilityServices - new.enabledAccessibilityServices
        for (pkg in addedA11y) {
            changes.add(ConfigChange(
                type = ConfigChangeType.ACCESSIBILITY_SERVICE_ADDED,
                severity = SignalSeverity.HIGH,
                description = "Povolena nová služba usnadnění přístupu: $pkg",
                newValue = pkg
            ))
        }
        for (pkg in removedA11y) {
            changes.add(ConfigChange(
                type = ConfigChangeType.ACCESSIBILITY_SERVICE_REMOVED,
                severity = SignalSeverity.LOW,
                description = "Služba usnadnění přístupu zakázána: $pkg",
                oldValue = pkg
            ))
        }

        // Notification listener changes
        val addedNotif = new.enabledNotificationListeners - old.enabledNotificationListeners
        val removedNotif = old.enabledNotificationListeners - new.enabledNotificationListeners
        for (pkg in addedNotif) {
            changes.add(ConfigChange(
                type = ConfigChangeType.NOTIFICATION_LISTENER_ADDED,
                severity = SignalSeverity.MEDIUM,
                description = "Povoleno nové čtení notifikací: $pkg",
                newValue = pkg
            ))
        }
        for (pkg in removedNotif) {
            changes.add(ConfigChange(
                type = ConfigChangeType.NOTIFICATION_LISTENER_REMOVED,
                severity = SignalSeverity.LOW,
                description = "Čtení notifikací zakázáno: $pkg",
                oldValue = pkg
            ))
        }

        // Default app changes
        if (old.defaultSmsApp != new.defaultSmsApp) {
            changes.add(ConfigChange(
                type = ConfigChangeType.DEFAULT_SMS_CHANGED,
                severity = SignalSeverity.HIGH,
                description = "Změna výchozí SMS aplikace",
                oldValue = old.defaultSmsApp,
                newValue = new.defaultSmsApp
            ))
        }
        if (old.defaultDialerApp != new.defaultDialerApp) {
            changes.add(ConfigChange(
                type = ConfigChangeType.DEFAULT_DIALER_CHANGED,
                severity = SignalSeverity.MEDIUM,
                description = "Změna výchozí aplikace telefonu",
                oldValue = old.defaultDialerApp,
                newValue = new.defaultDialerApp
            ))
        }

        // Developer options
        if (old.developerOptionsEnabled != new.developerOptionsEnabled) {
            changes.add(ConfigChange(
                type = ConfigChangeType.DEVELOPER_OPTIONS_CHANGED,
                severity = SignalSeverity.MEDIUM,
                description = if (new.developerOptionsEnabled) "Vývojářské možnosti zapnuty" else "Vývojářské možnosti vypnuty",
                oldValue = old.developerOptionsEnabled.toString(),
                newValue = new.developerOptionsEnabled.toString()
            ))
        }
        if (old.usbDebuggingEnabled != new.usbDebuggingEnabled) {
            changes.add(ConfigChange(
                type = ConfigChangeType.USB_DEBUGGING_CHANGED,
                severity = SignalSeverity.MEDIUM,
                description = if (new.usbDebuggingEnabled) "USB ladění zapnuto" else "USB ladění vypnuto",
                oldValue = old.usbDebuggingEnabled.toString(),
                newValue = new.usbDebuggingEnabled.toString()
            ))
        }
        if (old.installFromUnknownSourcesEnabled != new.installFromUnknownSourcesEnabled) {
            changes.add(ConfigChange(
                type = ConfigChangeType.UNKNOWN_SOURCES_CHANGED,
                severity = SignalSeverity.HIGH,
                description = if (new.installFromUnknownSourcesEnabled)
                    "Instalace z neznámých zdrojů povolena" else "Instalace z neznámých zdrojů zakázána",
                oldValue = old.installFromUnknownSourcesEnabled.toString(),
                newValue = new.installFromUnknownSourcesEnabled.toString()
            ))
        }

        return ConfigDelta(
            hasChanges = changes.isNotEmpty(),
            changes = changes
        )
    }

    /**
     * Convert config changes to SecuritySignals for the incident pipeline.
     */
    fun changesToSignals(delta: ConfigDelta): List<SecuritySignal> {
        return delta.changes.map { change ->
            SecuritySignal(
                source = SignalSource.CONFIG_BASELINE,
                type = mapChangeToSignalType(change.type),
                severity = change.severity,
                summary = change.description,
                details = buildMap {
                    change.oldValue?.let { put("old", it) }
                    change.newValue?.let { put("new", it) }
                }
            )
        }
    }

    private fun mapChangeToSignalType(changeType: ConfigChangeType): SignalType = when (changeType) {
        ConfigChangeType.CA_CERT_ADDED -> SignalType.USER_CA_CERT_ADDED
        ConfigChangeType.CA_CERT_REMOVED -> SignalType.USER_CA_CERT_REMOVED
        ConfigChangeType.PRIVATE_DNS_CHANGED -> SignalType.PRIVATE_DNS_CHANGED
        ConfigChangeType.VPN_ACTIVATED, ConfigChangeType.VPN_DEACTIVATED -> SignalType.VPN_STATE_CHANGED
        ConfigChangeType.PROXY_CONFIGURED, ConfigChangeType.PROXY_REMOVED -> SignalType.WIFI_PROXY_DETECTED
        ConfigChangeType.ACCESSIBILITY_SERVICE_ADDED,
        ConfigChangeType.ACCESSIBILITY_SERVICE_REMOVED -> SignalType.UNKNOWN_ACCESSIBILITY_SERVICE
        ConfigChangeType.NOTIFICATION_LISTENER_ADDED,
        ConfigChangeType.NOTIFICATION_LISTENER_REMOVED -> SignalType.UNKNOWN_ACCESSIBILITY_SERVICE
        ConfigChangeType.DEFAULT_SMS_CHANGED,
        ConfigChangeType.DEFAULT_DIALER_CHANGED -> SignalType.DEFAULT_APP_CHANGED
        ConfigChangeType.DEVELOPER_OPTIONS_CHANGED -> SignalType.DEVELOPER_OPTIONS_ENABLED
        ConfigChangeType.USB_DEBUGGING_CHANGED -> SignalType.USB_DEBUGGING_ENABLED
        ConfigChangeType.UNKNOWN_SOURCES_CHANGED -> SignalType.DEVELOPER_OPTIONS_ENABLED
    }

    // ══════════════════════════════════════════════════════════
    //  Individual checks
    // ══════════════════════════════════════════════════════════

    /**
     * Get SHA-256 fingerprints of user-installed CA certificates.
     * User CA certs indicate corporate proxy, debugging tool, or MITM attack.
     */
    fun getUserCaCertFingerprints(): Set<String> {
        return try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null)
            val fingerprints = mutableSetOf<String>()
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                // User-installed certs have aliases starting with "user:"
                if (alias.startsWith("user:")) {
                    val cert = keyStore.getCertificate(alias) as? X509Certificate
                    if (cert != null) {
                        val digest = MessageDigest.getInstance("SHA-256")
                        val fp = digest.digest(cert.encoded)
                            .joinToString("") { "%02x".format(it) }
                        fingerprints.add(fp)
                    }
                }
            }
            fingerprints
        } catch (_: Exception) {
            emptySet()
        }
    }

    /** Get Private DNS mode (API 28+) */
    private fun getPrivateDnsMode(): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                Settings.Global.getString(context.contentResolver, "private_dns_mode")
            } catch (_: Exception) {
                null
            }
        } else null
    }

    /** Get Private DNS hostname (if strict mode) */
    private fun getPrivateDnsHostname(): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                Settings.Global.getString(context.contentResolver, "private_dns_specifier")
            } catch (_: Exception) {
                null
            }
        } else null
    }

    /** Check if VPN is currently active */
    private fun isVpnActive(): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false
            val activeNetwork = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } catch (_: Exception) {
            false
        }
    }

    /** Check if a global HTTP proxy is configured */
    @SuppressLint("HardwareIds")
    private fun isGlobalProxyConfigured(): Boolean {
        return try {
            val host = Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
            !host.isNullOrBlank() && host != ":0"
        } catch (_: Exception) {
            false
        }
    }

    /** Get proxy host if configured */
    private fun getProxyHost(): String? {
        return try {
            val host = Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
            if (!host.isNullOrBlank() && host != ":0") host else null
        } catch (_: Exception) {
            null
        }
    }

    /** Check if developer options are enabled */
    private fun isDeveloperOptionsEnabled(): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
        } catch (_: Exception) {
            false
        }
    }

    /** Check if USB debugging is enabled */
    private fun isUsbDebuggingEnabled(): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (_: Exception) {
            false
        }
    }

    /** Check if install from unknown sources is enabled (pre-Oreo global setting) */
    @Suppress("DEPRECATION")
    private fun isUnknownSourcesEnabled(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) != 0
            } else {
                // On O+, this is per-app, so we check if any app has it
                // For now, return false (per-app check would need REQUEST_INSTALL_PACKAGES audit)
                false
            }
        } catch (_: Exception) {
            false
        }
    }
}
