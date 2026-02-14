package com.cybersentinel.app.domain.capability

import javax.inject.Inject
import javax.inject.Singleton

/**
 * CapabilityTier — static device classification for LLM capability.
 *
 * Determined once from StaticDeviceProfile. Does NOT change at runtime.
 * Runtime conditions are handled separately by FeatureGatekeeper.
 */
enum class CapabilityTier(val label: String, val allowsLlm: Boolean) {
    /**
     * TIER_0: LLM OFF — device cannot run inference.
     * Criteria: RAM < 4GB OR 32-bit only OR SDK < 26
     */
    TIER_0("Základní (bez AI)", false),

    /**
     * TIER_1: Tiny LLM on-demand with hard runtime gate.
     * Criteria: 4-8GB RAM, arm64, SDK ≥ 26
     * Runtime gate: available RAM < 600MB → fallback to template
     */
    TIER_1("Střední (AI na vyžádání)", true),

    /**
     * TIER_2: Larger model available, still on-demand + runtime gate.
     * Criteria: ≥ 8GB RAM, arm64, SDK ≥ 26
     * Runtime gate: available RAM < 800MB → fallback to template
     */
    TIER_2("Vysoký (AI dostupné)", true)
}

/**
 * Runtime gate decision — can LLM inference proceed RIGHT NOW?
 */
data class GateDecision(
    /** Whether LLM inference is allowed */
    val allowed: Boolean,
    /** Reason for the decision (for logging/debugging) */
    val reason: String,
    /** The gate rule that made the decision */
    val rule: GateRule
)

/**
 * Which gate rule determined the outcome.
 */
enum class GateRule {
    /** Static tier doesn't support LLM */
    TIER_BLOCKED,
    /** Kill switch is active for the current model version */
    KILL_SWITCH,
    /** User manually disabled AI */
    USER_DISABLED,
    /** Insufficient available RAM at runtime */
    LOW_RAM,
    /** Device in power saver mode */
    POWER_SAVER,
    /** Thermal throttling detected */
    THERMAL_THROTTLE,
    /** App is in background — conserve resources */
    BACKGROUND_RESTRICTED,
    /** All checks passed — LLM inference allowed */
    ALLOWED
}

/**
 * Kill switch state for remotely disabling specific LLM model versions.
 *
 * In production, this would be backed by RemoteConfig / feature flags.
 * For now, it's a local interface that tests and the orchestrator can use.
 */
interface KillSwitchProvider {
    /**
     * Check if a specific model version is disabled.
     *
     * @param modelId Identifier of the LLM model (e.g., "cybersentinel-tiny-v1")
     * @return true if this model version should NOT be used
     */
    fun isModelDisabled(modelId: String): Boolean
}

/**
 * Default kill switch — nothing disabled. Used until remote config is integrated.
 */
class DefaultKillSwitchProvider : KillSwitchProvider {
    override fun isModelDisabled(modelId: String): Boolean = false
}

/**
 * FeatureGatekeeper — two-stage gate for LLM inference decisions.
 *
 * Stage 1 (Static): Determine CapabilityTier from StaticDeviceProfile (once at startup)
 * Stage 2 (Runtime): Check runtime conditions before each inference call
 *
 * Additional overrides:
 *  - Kill switch: remotely disable specific model versions
 *  - User toggle: manual AI ON/OFF preference
 *
 * Thread safety: Uses volatile reads for state. Safe for concurrent access.
 */
@Singleton
open class FeatureGatekeeper @Inject constructor(
    private val deviceProfiler: DeviceProfiler
) {

    // ── Configurable thresholds ──

    /** Minimum available RAM (MB) for TIER_1 to proceed */
    private val tier1RamThresholdMb = 600L

    /** Minimum available RAM (MB) for TIER_2 to proceed */
    private val tier2RamThresholdMb = 800L

    /** Minimum total RAM (MB) to qualify for LLM at all */
    private val minTotalRamForLlmMb = 4000L

    /** Total RAM (MB) threshold for TIER_2 */
    private val tier2TotalRamMb = 8000L

    // ── State ──

    @Volatile
    private var cachedTier: CapabilityTier? = null

    @Volatile
    var killSwitchProvider: KillSwitchProvider = DefaultKillSwitchProvider()

    @Volatile
    open var userLlmEnabled: Boolean = true

    // ══════════════════════════════════════════════════════════
    //  Stage 1: Static tier determination
    // ══════════════════════════════════════════════════════════

    /**
     * Determine the device's capability tier. Computed once, cached.
     */
    open fun getCapabilityTier(): CapabilityTier {
        cachedTier?.let { return it }
        return computeTier().also { cachedTier = it }
    }

    /**
     * Compute tier from static profile. Exposed for testing.
     */
    fun computeTierFromProfile(profile: StaticDeviceProfile): CapabilityTier {
        // Rule 1: Insufficient RAM → TIER_0
        if (profile.totalRamMb < minTotalRamForLlmMb) return CapabilityTier.TIER_0

        // Rule 2: 32-bit only → TIER_0 (llama.cpp requires 64-bit for efficient inference)
        if (!profile.is64Bit) return CapabilityTier.TIER_0

        // Rule 3: ≥ 8GB RAM + 64-bit → TIER_2
        if (profile.totalRamMb >= tier2TotalRamMb) return CapabilityTier.TIER_2

        // Rule 4: 4-8GB RAM + 64-bit → TIER_1
        return CapabilityTier.TIER_1
    }

    private fun computeTier(): CapabilityTier {
        val profile = deviceProfiler.getStaticProfile()
        return computeTierFromProfile(profile)
    }

    // ══════════════════════════════════════════════════════════
    //  Stage 2: Runtime gate
    // ══════════════════════════════════════════════════════════

    /**
     * Full gate check: Can LLM inference proceed right now?
     *
     * Checks in order (first failing rule wins):
     *  1. Static tier allows LLM?
     *  2. User toggle enabled?
     *  3. Kill switch for model version?
     *  4. Power saver mode?
     *  5. Thermal throttling?
     *  6. Background restriction?
     *  7. Available RAM sufficient?
     *
     * @param modelId The LLM model version to check kill switch for
     * @param isInBackground Whether the app is currently in background
     * @return GateDecision with allow/deny and reason
     */
    open fun checkGate(
        modelId: String = "default",
        isInBackground: Boolean = false
    ): GateDecision {
        // 1. Static tier
        val tier = getCapabilityTier()
        if (!tier.allowsLlm) {
            return GateDecision(
                allowed = false,
                reason = "Zařízení v kategorii ${tier.label} — AI analýza není dostupná",
                rule = GateRule.TIER_BLOCKED
            )
        }

        // 2. User toggle
        if (!userLlmEnabled) {
            return GateDecision(
                allowed = false,
                reason = "AI analýza je vypnuta uživatelem",
                rule = GateRule.USER_DISABLED
            )
        }

        // 3. Kill switch
        if (killSwitchProvider.isModelDisabled(modelId)) {
            return GateDecision(
                allowed = false,
                reason = "Model $modelId je dočasně zakázán",
                rule = GateRule.KILL_SWITCH
            )
        }

        // 4-7. Runtime conditions
        val snapshot = deviceProfiler.getRuntimeSnapshot(isInBackground)

        if (snapshot.isPowerSaverActive) {
            return GateDecision(
                allowed = false,
                reason = "Režim úspory baterie je aktivní",
                rule = GateRule.POWER_SAVER
            )
        }

        if (snapshot.isThermalThrottling) {
            return GateDecision(
                allowed = false,
                reason = "Zařízení přehřáto — inference odložena",
                rule = GateRule.THERMAL_THROTTLE
            )
        }

        if (snapshot.isInBackground) {
            return GateDecision(
                allowed = false,
                reason = "Aplikace běží na pozadí — šetříme prostředky",
                rule = GateRule.BACKGROUND_RESTRICTED
            )
        }

        // RAM threshold depends on tier
        val ramThreshold = when (tier) {
            CapabilityTier.TIER_1 -> tier1RamThresholdMb
            CapabilityTier.TIER_2 -> tier2RamThresholdMb
            CapabilityTier.TIER_0 -> Long.MAX_VALUE // unreachable
        }

        if (snapshot.availableRamMb < ramThreshold) {
            return GateDecision(
                allowed = false,
                reason = "Nedostatek volné RAM (${snapshot.availableRamMb}MB < ${ramThreshold}MB)",
                rule = GateRule.LOW_RAM
            )
        }

        // All checks passed
        return GateDecision(
            allowed = true,
            reason = "AI analýza povolena (${tier.label}, ${snapshot.availableRamMb}MB volné RAM)",
            rule = GateRule.ALLOWED
        )
    }

    /**
     * Quick check — is LLM theoretically available on this device?
     * Only checks static tier, not runtime conditions.
     */
    fun isLlmCapable(): Boolean = getCapabilityTier().allowsLlm

    /**
     * Reset cached tier — used for testing or after device profile changes.
     */
    fun resetCache() {
        cachedTier = null
    }
}
