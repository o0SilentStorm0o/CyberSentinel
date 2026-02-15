package com.cybersentinel.app.domain.security

import java.util.UUID

/**
 * Incident Pipeline — standardized 3-level evidence model.
 *
 * Level 1: SecuritySignal — single atomic observation (e.g., "cert changed")
 * Level 2: SecurityEvent — time-bounded group of signals from one source
 * Level 3: SecurityIncident — aggregated event with ranked hypotheses
 *
 * Flow: Scanner/Baseline/Config → Signals → Events → Incidents → UI/Sentinel
 *
 * Design: Pure data classes. No side effects. Deterministic.
 */

// ══════════════════════════════════════════════════════════
//  Level 1: SecuritySignal — atomic observation
// ══════════════════════════════════════════════════════════

/**
 * A single, atomic security-relevant observation.
 * Signals are cheap to produce — every detector emits them freely.
 */
data class SecuritySignal(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val source: SignalSource,
    val type: SignalType,
    val severity: SignalSeverity,
    val packageName: String? = null,
    val summary: String,
    val details: Map<String, String> = emptyMap()
)

/** Where the signal came from */
enum class SignalSource {
    /** App scanner (permissions, cert, components) */
    APP_SCANNER,
    /** Baseline manager (change detection) */
    BASELINE,
    /** Special access inspector */
    SPECIAL_ACCESS,
    /** Config baseline engine (CA certs, DNS, VPN) */
    CONFIG_BASELINE,
    /** Trust evidence engine */
    TRUST_ENGINE,
    /** Sleeping sentinel (behavioral, future) */
    SENTINEL,
    /** Device security analyzer */
    DEVICE_ANALYZER
}

enum class SignalType {
    // ── App-level signals ──
    CERT_CHANGE,
    VERSION_ROLLBACK,
    INSTALLER_CHANGE,
    HIGH_RISK_PERM_ADDED,
    SPECIAL_ACCESS_ENABLED,
    SPECIAL_ACCESS_DISABLED,
    EXPORTED_SURFACE_CHANGE,
    NEW_APP_INSTALLED,
    APP_REMOVED,
    SUSPICIOUS_NATIVE_LIB,
    DEBUG_SIGNATURE,
    COMBO_DETECTED,
    
    // ── Config-level signals ──
    USER_CA_CERT_ADDED,
    USER_CA_CERT_REMOVED,
    PRIVATE_DNS_CHANGED,
    VPN_STATE_CHANGED,
    WIFI_PROXY_DETECTED,
    UNKNOWN_ACCESSIBILITY_SERVICE,
    DEFAULT_APP_CHANGED,
    
    // ── Device-level signals ──
    ROOT_DETECTED,
    BOOTLOADER_UNLOCKED,
    DEVELOPER_OPTIONS_ENABLED,
    USB_DEBUGGING_ENABLED,
    
    // ── Dropper / Loader signals ──
    /** App loads code dynamically (DexClassLoader, reflection) */
    DYNAMIC_CODE_LOADING,
    /** Fresh install immediately requests high-risk permissions */
    FRESH_INSTALL_RISKY_PERM,
    /** Significant network traffic right after install (payload fetch) */
    NETWORK_AFTER_INSTALL,
    /** Staged payload detected: minimal APK → post-install expansion */
    STAGED_PAYLOAD_PATTERN,
    /** App registers BOOT_COMPLETED receiver for persistence */
    BOOT_PERSISTENCE,
    /** Post-install escalation: new perms requested after initial quiet period */
    POST_INSTALL_PERMISSION_ESCALATION,

    // ── Behavioral signals (Sentinel, future) ──
    BATTERY_DRAIN_ANOMALY,
    NETWORK_BURST_ANOMALY,
    EXCESSIVE_WAKEUPS,
    UNUSUAL_CONTEXT
}

enum class SignalSeverity(val weight: Int) {
    CRITICAL(40),
    HIGH(25),
    MEDIUM(15),
    LOW(5),
    INFO(1)
}

// ══════════════════════════════════════════════════════════
//  Level 2: SecurityEvent — time-bounded group
// ══════════════════════════════════════════════════════════

/**
 * A time-bounded security event composed of one or more signals.
 * Events represent "something happened" — they have a start and optional end time.
 */
data class SecurityEvent(
    val id: String = UUID.randomUUID().toString(),
    val startTime: Long = System.currentTimeMillis(),
    val endTime: Long? = null,
    val source: SignalSource,
    val type: EventType,
    val severity: SignalSeverity,
    val packageName: String? = null,
    val summary: String,
    val signals: List<SecuritySignal> = emptyList(),
    val metadata: Map<String, String> = emptyMap(),
    /** True if this event was already promoted to an incident */
    val isPromoted: Boolean = false
)

enum class EventType {
    // ── Single-app events ──
    /** App update with suspicious characteristics */
    SUSPICIOUS_UPDATE,
    /** App appears with concerning profile */
    SUSPICIOUS_INSTALL,
    /** App gained new dangerous capabilities */
    CAPABILITY_ESCALATION,
    /** Special access was enabled for an app */
    SPECIAL_ACCESS_GRANT,
    /** Stalkerware pattern detected */
    STALKERWARE_PATTERN,
    /** Dropper pattern detected (install + accessibility) */
    DROPPER_PATTERN,
    /** Overlay + phishing pattern */
    OVERLAY_ATTACK_PATTERN,
    /** Staged payload: app installs then escalates over time */
    STAGED_PAYLOAD,
    /** Loader behavior: benign app fetches and executes remote code */
    LOADER_BEHAVIOR,

    // ── Config events ──
    /** Device config changed in suspicious way */
    CONFIG_TAMPER,
    /** New CA certificate installed */
    CA_CERT_INSTALLED,
    /** VPN activated by suspicious app */
    SUSPICIOUS_VPN,

    // ── Device events ──
    /** Device integrity compromised */
    DEVICE_COMPROMISE,

    // ── Behavioral events (Sentinel, future) ──
    /** Anomalous app behavior detected */
    BEHAVIORAL_ANOMALY,

    // ── Generic ──
    /** Doesn't fit other categories */
    OTHER
}

// ══════════════════════════════════════════════════════════
//  Level 3: SecurityIncident — aggregated with hypotheses
// ══════════════════════════════════════════════════════════

/**
 * A security incident — the highest-level assessment.
 * Contains ranked hypotheses explaining what might be happening.
 * Created by RootCauseResolver from events + app knowledge + config.
 */
data class SecurityIncident(
    val id: String = UUID.randomUUID().toString(),
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val severity: IncidentSeverity,
    val status: IncidentStatus = IncidentStatus.OPEN,
    val title: String,
    val summary: String,
    /** Primary affected package (if app-level) */
    val packageName: String? = null,
    /** All affected packages */
    val affectedPackages: List<String> = emptyList(),
    /** Events that contributed to this incident */
    val events: List<SecurityEvent> = emptyList(),
    /** Ranked hypotheses — first is most likely */
    val hypotheses: List<Hypothesis> = emptyList(),
    /** Recommended actions for the user */
    val recommendedActions: List<RecommendedAction> = emptyList()
)

enum class IncidentSeverity(val label: String, val emoji: String) {
    CRITICAL("Kritický", "🔴"),
    HIGH("Vysoký", "🟠"),
    MEDIUM("Střední", "🟡"),
    LOW("Nízký", "🔵"),
    INFO("Informační", "⚪")
}

enum class IncidentStatus {
    OPEN,
    INVESTIGATING,
    RESOLVED,
    DISMISSED,
    FALSE_POSITIVE
}

/**
 * A ranked hypothesis explaining what might be happening.
 * Confidence is 0.0-1.0, and hypotheses are sorted by confidence descending.
 */
data class Hypothesis(
    /** Human-readable name of the hypothesis */
    val name: String,
    /** Detailed explanation */
    val description: String,
    /** Confidence level 0.0-1.0 */
    val confidence: Double,
    /** Evidence supporting this hypothesis */
    val supportingEvidence: List<String>,
    /** Evidence against this hypothesis */
    val contradictingEvidence: List<String> = emptyList(),
    /** MITRE ATT&CK technique IDs if applicable */
    val mitreTechniques: List<String> = emptyList()
)

/**
 * An actionable recommendation for the user.
 */
data class RecommendedAction(
    val priority: Int,
    val type: ActionCategory,
    val title: String,
    val description: String,
    /** Package to act on (if app-level) */
    val targetPackage: String? = null
)

enum class ActionCategory {
    UNINSTALL,
    DISABLE,
    REVOKE_PERMISSION,
    REVOKE_SPECIAL_ACCESS,
    CHECK_SETTINGS,
    REINSTALL_FROM_STORE,
    FACTORY_RESET,
    MONITOR,
    INFORM
}
