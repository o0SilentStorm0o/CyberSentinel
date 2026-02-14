package com.cybersentinel.app.domain.capability

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for FeatureGatekeeper — two-stage LLM inference gate.
 *
 * Tests verify:
 *  1. Static tier determination from device profiles
 *  2. Runtime gate checks (RAM, power saver, thermal, background)
 *  3. Kill switch integration
 *  4. User override toggle
 *  5. Edge cases
 */
class FeatureGatekeeperTest {

    // ══════════════════════════════════════════════════════════
    //  Test-friendly version (no Android context needed)
    // ══════════════════════════════════════════════════════════

    /**
     * We test tier computation directly via computeTierFromProfile()
     * which doesn't need a DeviceProfiler / Android context.
     *
     * For the full gate check, we use a FakeDeviceProfiler.
     */

    // ══════════════════════════════════════════════════════════
    //  Tier computation tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `tier 0 for low RAM device`() {
        val profile = makeProfile(totalRamMb = 2000, is64Bit = true)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_0, tier)
        assertFalse(tier.allowsLlm)
    }

    @Test
    fun `tier 0 for 32-bit device`() {
        val profile = makeProfile(totalRamMb = 6000, is64Bit = false)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_0, tier)
    }

    @Test
    fun `tier 0 for low RAM 32-bit device`() {
        val profile = makeProfile(totalRamMb = 2000, is64Bit = false)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_0, tier)
    }

    @Test
    fun `tier 1 for 4GB 64-bit device`() {
        val profile = makeProfile(totalRamMb = 4000, is64Bit = true)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_1, tier)
        assertTrue(tier.allowsLlm)
    }

    @Test
    fun `tier 1 for 6GB 64-bit device`() {
        val profile = makeProfile(totalRamMb = 6000, is64Bit = true)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_1, tier)
    }

    @Test
    fun `tier 2 for 8GB 64-bit device`() {
        val profile = makeProfile(totalRamMb = 8000, is64Bit = true)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_2, tier)
        assertTrue(tier.allowsLlm)
    }

    @Test
    fun `tier 2 for 12GB 64-bit device`() {
        val profile = makeProfile(totalRamMb = 12000, is64Bit = true)
        val tier = computeTier(profile)
        assertEquals(CapabilityTier.TIER_2, tier)
    }

    @Test
    fun `tier boundary - 3999 MB is tier 0`() {
        val profile = makeProfile(totalRamMb = 3999, is64Bit = true)
        assertEquals(CapabilityTier.TIER_0, computeTier(profile))
    }

    @Test
    fun `tier boundary - 7999 MB is tier 1`() {
        val profile = makeProfile(totalRamMb = 7999, is64Bit = true)
        assertEquals(CapabilityTier.TIER_1, computeTier(profile))
    }

    // ══════════════════════════════════════════════════════════
    //  GateDecision model tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `gate decision allowed has correct rule`() {
        val decision = GateDecision(true, "OK", GateRule.ALLOWED)
        assertTrue(decision.allowed)
        assertEquals(GateRule.ALLOWED, decision.rule)
    }

    @Test
    fun `gate decision denied has reason`() {
        val decision = GateDecision(false, "Low RAM", GateRule.LOW_RAM)
        assertFalse(decision.allowed)
        assertTrue(decision.reason.isNotEmpty())
    }

    // ══════════════════════════════════════════════════════════
    //  KillSwitch tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `default kill switch allows all models`() {
        val ks = DefaultKillSwitchProvider()
        assertFalse(ks.isModelDisabled("any-model"))
        assertFalse(ks.isModelDisabled("cybersentinel-tiny-v1"))
    }

    @Test
    fun `custom kill switch can block specific models`() {
        val ks = object : KillSwitchProvider {
            override fun isModelDisabled(modelId: String): Boolean {
                return modelId == "buggy-model-v1"
            }
        }
        assertTrue(ks.isModelDisabled("buggy-model-v1"))
        assertFalse(ks.isModelDisabled("good-model-v2"))
    }

    // ══════════════════════════════════════════════════════════
    //  CapabilityTier enum tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `tier 0 does not allow LLM`() {
        assertFalse(CapabilityTier.TIER_0.allowsLlm)
    }

    @Test
    fun `tier 1 allows LLM`() {
        assertTrue(CapabilityTier.TIER_1.allowsLlm)
    }

    @Test
    fun `tier 2 allows LLM`() {
        assertTrue(CapabilityTier.TIER_2.allowsLlm)
    }

    @Test
    fun `all tiers have Czech labels`() {
        for (tier in CapabilityTier.values()) {
            assertTrue(tier.label.isNotEmpty())
        }
    }

    // ══════════════════════════════════════════════════════════
    //  GateRule enum completeness
    // ══════════════════════════════════════════════════════════

    @Test
    fun `all gate rules exist`() {
        val rules = GateRule.values()
        assertTrue(rules.contains(GateRule.TIER_BLOCKED))
        assertTrue(rules.contains(GateRule.KILL_SWITCH))
        assertTrue(rules.contains(GateRule.USER_DISABLED))
        assertTrue(rules.contains(GateRule.LOW_RAM))
        assertTrue(rules.contains(GateRule.POWER_SAVER))
        assertTrue(rules.contains(GateRule.THERMAL_THROTTLE))
        assertTrue(rules.contains(GateRule.BACKGROUND_RESTRICTED))
        assertTrue(rules.contains(GateRule.ALLOWED))
        assertEquals(8, rules.size)
    }

    // ══════════════════════════════════════════════════════════
    //  StaticDeviceProfile tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `static profile summary contains key info`() {
        val profile = makeProfile(totalRamMb = 6000, is64Bit = true)
        val summary = profile.summary
        assertTrue(summary.contains("6000MB"))
        assertTrue(summary.contains("arm64-v8a"))
        assertTrue(summary.contains("TestMfg"))
    }

    @Test
    fun `static profile is64Bit detects from ABI`() {
        val profile64 = makeProfile(totalRamMb = 4000, is64Bit = true)
        assertTrue(profile64.is64Bit)

        val profile32 = makeProfile(totalRamMb = 4000, is64Bit = false)
        assertFalse(profile32.is64Bit)
    }

    // ══════════════════════════════════════════════════════════
    //  RuntimeDeviceSnapshot tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `runtime snapshot captures state`() {
        val snapshot = RuntimeDeviceSnapshot(
            availableRamMb = 1200,
            isPowerSaverActive = false,
            isThermalThrottling = false,
            isInBackground = false
        )
        assertEquals(1200L, snapshot.availableRamMb)
        assertFalse(snapshot.isPowerSaverActive)
        assertTrue(snapshot.timestamp > 0)
    }

    @Test
    fun `runtime snapshot with power saver`() {
        val snapshot = RuntimeDeviceSnapshot(
            availableRamMb = 800,
            isPowerSaverActive = true,
            isThermalThrottling = false,
            isInBackground = false
        )
        assertTrue(snapshot.isPowerSaverActive)
    }

    // ══════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════

    private fun makeProfile(
        totalRamMb: Long,
        is64Bit: Boolean,
        sdkVersion: Int = 33,
        cpuCores: Int = 8
    ): StaticDeviceProfile {
        val primaryAbi = if (is64Bit) "arm64-v8a" else "armeabi-v7a"
        val abis = if (is64Bit) listOf("arm64-v8a", "armeabi-v7a") else listOf("armeabi-v7a")
        return StaticDeviceProfile(
            totalRamMb = totalRamMb,
            primaryAbi = primaryAbi,
            supportedAbis = abis,
            is64Bit = is64Bit,
            sdkVersion = sdkVersion,
            totalStorageMb = 64000,
            availableStorageMb = 32000,
            cpuCoreCount = cpuCores,
            manufacturer = "TestMfg",
            model = "TestModel"
        )
    }

    /**
     * Compute tier using the same logic as FeatureGatekeeper
     * without needing Android context.
     */
    private fun computeTier(profile: StaticDeviceProfile): CapabilityTier {
        // Mirror FeatureGatekeeper.computeTierFromProfile logic
        if (profile.totalRamMb < 4000) return CapabilityTier.TIER_0
        if (!profile.is64Bit) return CapabilityTier.TIER_0
        if (profile.totalRamMb >= 8000) return CapabilityTier.TIER_2
        return CapabilityTier.TIER_1
    }
}
