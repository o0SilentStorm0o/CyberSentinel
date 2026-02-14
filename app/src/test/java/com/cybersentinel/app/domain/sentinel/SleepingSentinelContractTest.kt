package com.cybersentinel.app.domain.sentinel

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Sleeping Sentinel contract — data classes and interfaces.
 */
class SleepingSentinelContractTest {

    // ══════════════════════════════════════════════════════════
    //  SentinelSample tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `SentinelSample has correct structure`() {
        val sample = SentinelSample(
            deviceState = DeviceStateSample(
                batteryLevel = 75,
                isCharging = false,
                screenOn = true,
                networkType = NetworkType.WIFI,
                vpnActive = false,
                totalRxBytes = 1_000_000,
                totalTxBytes = 500_000,
                uptimeMillis = 3_600_000
            ),
            appSamples = listOf(
                AppStateSample(
                    packageName = "com.example.app",
                    uid = 10001,
                    rxBytes = 50_000,
                    txBytes = 10_000,
                    foregroundServiceRunning = false,
                    wakelockHeld = false,
                    cpuTimeMs = 500,
                    lastActivityTs = null
                )
            )
        )

        assertEquals(75, sample.deviceState.batteryLevel)
        assertEquals(1, sample.appSamples.size)
        assertEquals("com.example.app", sample.appSamples.first().packageName)
    }

    @Test
    fun `SentinelSample has default timestamp`() {
        val before = System.currentTimeMillis()
        val sample = SentinelSample(
            deviceState = DeviceStateSample(
                batteryLevel = 50, isCharging = true, screenOn = false,
                networkType = NetworkType.NONE, vpnActive = false,
                totalRxBytes = 0, totalTxBytes = 0, uptimeMillis = 0
            ),
            appSamples = emptyList()
        )
        val after = System.currentTimeMillis()
        assertTrue(sample.timestamp in before..after)
    }

    @Test
    fun `NetworkType has all expected values`() {
        assertEquals(5, NetworkType.entries.size)
        assertTrue(NetworkType.entries.contains(NetworkType.NONE))
        assertTrue(NetworkType.entries.contains(NetworkType.WIFI))
        assertTrue(NetworkType.entries.contains(NetworkType.MOBILE))
        assertTrue(NetworkType.entries.contains(NetworkType.VPN))
        assertTrue(NetworkType.entries.contains(NetworkType.OTHER))
    }

    @Test
    fun `DeviceStateSample captures all fields`() {
        val state = DeviceStateSample(
            batteryLevel = 42,
            isCharging = true,
            screenOn = false,
            networkType = NetworkType.MOBILE,
            vpnActive = true,
            totalRxBytes = 999,
            totalTxBytes = 111,
            uptimeMillis = 12345
        )
        assertEquals(42, state.batteryLevel)
        assertTrue(state.isCharging)
        assertFalse(state.screenOn)
        assertEquals(NetworkType.MOBILE, state.networkType)
        assertTrue(state.vpnActive)
        assertEquals(999L, state.totalRxBytes)
        assertEquals(111L, state.totalTxBytes)
        assertEquals(12345L, state.uptimeMillis)
    }

    @Test
    fun `AppStateSample nullable lastActivityTs`() {
        val withTs = AppStateSample("a", 1, 0, 0, false, false, 0, 1000L)
        val withoutTs = AppStateSample("b", 2, 0, 0, false, false, 0, null)
        assertEquals(1000L, withTs.lastActivityTs)
        assertNull(withoutTs.lastActivityTs)
    }

    // ══════════════════════════════════════════════════════════
    //  BehaviorAnomaly tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `BatteryDrainWhileIdle has correct fields`() {
        val anomaly = BehaviorAnomaly.BatteryDrainWhileIdle(
            packageName = "com.evil.app",
            confidence = 0.8,
            drainPercentPerHour = 5.2,
            wasForeground = false
        )
        assertEquals("com.evil.app", anomaly.packageName)
        assertEquals(0.8, anomaly.confidence, 0.001)
        assertEquals(5.2, anomaly.drainPercentPerHour, 0.001)
        assertFalse(anomaly.wasForeground)
        assertTrue(anomaly.description.isNotEmpty())
    }

    @Test
    fun `NetworkBurstAtNight has correct fields`() {
        val now = System.currentTimeMillis()
        val anomaly = BehaviorAnomaly.NetworkBurstAtNight(
            packageName = "com.evil.app",
            confidence = 0.7,
            bytesTransferred = 1_000_000,
            windowStart = now - 3_600_000,
            windowEnd = now
        )
        assertEquals(1_000_000, anomaly.bytesTransferred)
        assertTrue(anomaly.windowEnd > anomaly.windowStart)
    }

    @Test
    fun `ExcessiveWakeupsPattern has correct fields`() {
        val anomaly = BehaviorAnomaly.ExcessiveWakeupsPattern(
            packageName = "com.evil.app",
            confidence = 0.6,
            wakelockMinutes = 45,
            windowMinutes = 60
        )
        assertEquals(45, anomaly.wakelockMinutes)
        assertEquals(60, anomaly.windowMinutes)
    }

    @Test
    fun `UnusualContext has correct fields`() {
        val anomaly = BehaviorAnomaly.UnusualContext(
            packageName = "com.evil.app",
            confidence = 0.5,
            contextDetail = "Accessibility service active but app not opened in 7 days"
        )
        assertTrue(anomaly.contextDetail.isNotEmpty())
    }

    @Test
    fun `BehaviorAnomaly sealed class covers all types`() {
        val anomalies: List<BehaviorAnomaly> = listOf(
            BehaviorAnomaly.BatteryDrainWhileIdle("a", confidence = 0.5, drainPercentPerHour = 1.0),
            BehaviorAnomaly.NetworkBurstAtNight("b", confidence = 0.5, bytesTransferred = 100, windowStart = 0, windowEnd = 1),
            BehaviorAnomaly.ExcessiveWakeupsPattern("c", confidence = 0.5, wakelockMinutes = 10, windowMinutes = 60),
            BehaviorAnomaly.UnusualContext("d", confidence = 0.5, contextDetail = "test")
        )
        assertEquals(4, anomalies.size)
        // Verify all have common fields
        anomalies.forEach { anomaly ->
            assertTrue(anomaly.packageName.isNotEmpty())
            assertTrue(anomaly.confidence in 0.0..1.0)
            assertTrue(anomaly.description.isNotEmpty())
        }
    }

    @Test
    fun `BehaviorAnomaly default descriptions are in Czech`() {
        val battery = BehaviorAnomaly.BatteryDrainWhileIdle("a", confidence = 0.5, drainPercentPerHour = 1.0)
        val network = BehaviorAnomaly.NetworkBurstAtNight("b", confidence = 0.5, bytesTransferred = 100, windowStart = 0, windowEnd = 1)
        val wakeup = BehaviorAnomaly.ExcessiveWakeupsPattern("c", confidence = 0.5, wakelockMinutes = 10, windowMinutes = 60)
        val context = BehaviorAnomaly.UnusualContext("d", confidence = 0.5, contextDetail = "test")

        // Verify descriptions contain Czech characters/words
        assertTrue(battery.description.contains("baterie"))
        assertTrue(network.description.contains("síťový"))
        assertTrue(wakeup.description.contains("procesoru"))
        assertTrue(context.description.contains("kontextu"))
    }

    // ══════════════════════════════════════════════════════════
    //  AppBehaviorBaseline tests
    // ══════════════════════════════════════════════════════════

    @Test
    fun `AppBehaviorBaseline has correct defaults`() {
        val baseline = AppBehaviorBaseline(
            packageName = "com.example.app",
            sampleCount = 100,
            firstSampleAt = 1000,
            lastSampleAt = 2000,
            avgNetworkBytesPerHour = 50_000.0,
            avgCpuTimePerHour = 1000.0,
            avgWakelockMinutesPerHour = 2.0,
            typicalActiveHours = setOf(8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
        )
        assertEquals(2.0, baseline.stdDevMultiplier, 0.001)
        assertEquals(10, baseline.typicalActiveHours.size)
    }

    @Test
    fun `AppBehaviorBaseline custom stdDevMultiplier`() {
        val baseline = AppBehaviorBaseline(
            packageName = "com.example.app",
            sampleCount = 50,
            firstSampleAt = 1000,
            lastSampleAt = 2000,
            avgNetworkBytesPerHour = 10_000.0,
            avgCpuTimePerHour = 500.0,
            avgWakelockMinutesPerHour = 1.0,
            typicalActiveHours = emptySet(),
            stdDevMultiplier = 3.0
        )
        assertEquals(3.0, baseline.stdDevMultiplier, 0.001)
        assertTrue(baseline.typicalActiveHours.isEmpty())
    }
}
