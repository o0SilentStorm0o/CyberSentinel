package com.cybersentinel.app.domain.llm

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for LlamaCppRuntime — Sprint C2-2 + C2-2.5 + C2-2.6.
 *
 * Note: These tests run in JVM (not on device), so:
 *  - No actual JNI calls (UnsatisfiedLinkError expected)
 *  - Build.SUPPORTED_ABIS is null/empty in JVM → isArm64Device() returns false
 *  - Tests focus on: ABI gating, unloaded state behavior, contract compliance,
 *    cancel support, timeout grace, cooldown, single-flight, JNI output parsing
 *
 * On-device/instrumented tests are in LlmPipelineSmokeTest (androidTest).
 */
class LlamaCppRuntimeTest {

    // ══════════════════════════════════════════════════════════
    //  ABI gating
    // ══════════════════════════════════════════════════════════

    @Test
    fun `isArm64Device returns false in JVM test environment`() {
        // In unit tests Build.SUPPORTED_ABIS is empty → not arm64
        assertFalse(LlamaCppRuntime.isArm64Device())
    }

    @Test
    fun `create returns null on non-arm64 device`() {
        // In unit tests, device is not arm64 → factory returns null
        val runtime = LlamaCppRuntime.create("/fake/path/model.gguf")
        assertNull("Should return null on non-arm64", runtime)
    }

    @Test
    fun `create returns null with custom context size on non-arm64`() {
        val runtime = LlamaCppRuntime.create("/fake/model.gguf", contextSize = 1024, nThreads = 2)
        assertNull(runtime)
    }

    // ══════════════════════════════════════════════════════════
    //  Unloaded state
    // ══════════════════════════════════════════════════════════

    @Test
    fun `createUnloaded produces runtime with nativeHandle zero`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        assertFalse("Unloaded runtime should not be available", runtime.isAvailable)
    }

    @Test
    fun `unloaded runtime runtimeId contains llama_cpp`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        assertTrue(
            "runtimeId should contain llama_cpp",
            runtime.runtimeId.contains("llama_cpp")
        )
    }

    @Test
    fun `unloaded runtime runtimeId contains arm64`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        assertTrue(
            "runtimeId should contain arm64",
            runtime.runtimeId.contains("arm64")
        )
    }

    @Test
    fun `unloaded runtime runInference returns failure`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val result = runtime.runInference("test prompt", InferenceConfig.SLOTS_DEFAULT)

        assertFalse("Should fail when not available", result.success)
        assertNotNull(result.error)
        assertTrue("Error should mention not available", result.error!!.contains("not available"))
    }

    @Test
    fun `shutdown on unloaded runtime is idempotent`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        // Should not throw
        runtime.shutdown()
        runtime.shutdown()
        runtime.shutdown()
        assertFalse(runtime.isAvailable)
    }

    @Test
    fun `cancelInference on unloaded runtime does not throw`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        runtime.cancelInference() // should be no-op
    }

    // ══════════════════════════════════════════════════════════
    //  LlmRuntime contract compliance
    // ══════════════════════════════════════════════════════════

    @Test
    fun `implements LlmRuntime interface`() {
        val runtime: LlmRuntime = LlamaCppRuntime.createUnloaded()
        assertNotNull(runtime.runtimeId)
        assertFalse(runtime.isAvailable)
    }

    @Test
    fun `runtimeId follows naming convention`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val pattern = Regex("llama_cpp_v\\d+_arm64")
        assertTrue(
            "runtimeId '${runtime.runtimeId}' should match pattern",
            pattern.matches(runtime.runtimeId)
        )
    }

    @Test
    fun `loadLibrary returns false in JVM test environment`() {
        // No native library in unit test classpath
        assertFalse(LlamaCppRuntime.loadLibrary())
    }

    // ══════════════════════════════════════════════════════════
    //  InferenceResult contract
    // ══════════════════════════════════════════════════════════

    @Test
    fun `failure result from unloaded runtime has correct structure`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val result = runtime.runInference("test", InferenceConfig.SLOTS_DEFAULT)

        assertFalse(result.success)
        assertTrue(result.rawOutput.isEmpty())
        assertNotNull(result.error)
        assertNull(result.tokensGenerated)
    }

    @Test
    fun `multiple runInference calls on unloaded runtime all fail gracefully`() {
        val runtime = LlamaCppRuntime.createUnloaded()

        repeat(5) {
            val result = runtime.runInference("prompt $it", InferenceConfig.SLOTS_DEFAULT)
            assertFalse("Run $it should fail", result.success)
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Config variants (C2-2.5: deterministic defaults)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `SLOTS_DEFAULT config has deterministic temperature`() {
        val config = InferenceConfig.SLOTS_DEFAULT
        assertEquals(160, config.maxNewTokens)
        assertEquals(0.0f, config.temperature, 0.001f)  // C2-2.5: greedy
        assertEquals(1.0f, config.topP, 0.001f)          // C2-2.5: no top-p filtering
        assertEquals(15_000L, config.timeoutMs)
    }

    @Test
    fun `TIER1_CONSERVATIVE config has deterministic temperature`() {
        val config = InferenceConfig.TIER1_CONSERVATIVE
        assertEquals(0.0f, config.temperature, 0.001f)  // C2-2.5: greedy
        assertEquals(1.0f, config.topP, 0.001f)          // C2-2.5: no top-p filtering
        assertTrue("TIER1 maxTokens should be ≤ SLOTS_DEFAULT",
            config.maxNewTokens <= InferenceConfig.SLOTS_DEFAULT.maxNewTokens)
        assertTrue("TIER1 timeout should be ≥ SLOTS_DEFAULT",
            config.timeoutMs >= InferenceConfig.SLOTS_DEFAULT.timeoutMs)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.5: Timeout grace and cancel support
    // ══════════════════════════════════════════════════════════

    @Test
    fun `TIMEOUT_GRACE_MS is positive`() {
        assertTrue("Grace period should be > 0", LlamaCppRuntime.TIMEOUT_GRACE_MS > 0)
    }

    @Test
    fun `TIMEOUT_GRACE_MS is reasonable (under 2 seconds)`() {
        assertTrue("Grace period should be < 2000ms", LlamaCppRuntime.TIMEOUT_GRACE_MS < 2000)
    }

    @Test
    fun `cancelInference after shutdown does not throw`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        runtime.shutdown()
        runtime.cancelInference() // Should be safe after shutdown
    }

    @Test
    fun `shutdown then runInference returns failure`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        runtime.shutdown()
        val result = runtime.runInference("test", InferenceConfig.SLOTS_DEFAULT)
        assertFalse(result.success)
    }

    // ══════════════════════════════════════════════════════════
    //  C2-2.6: Single-flight, cooldown, JNI output parsing
    // ══════════════════════════════════════════════════════════

    @Test
    fun `CANCEL_COOLDOWN_MS is positive and reasonable`() {
        assertTrue("Cooldown should be > 0", LlamaCppRuntime.CANCEL_COOLDOWN_MS > 0)
        assertTrue("Cooldown should be < 1000ms", LlamaCppRuntime.CANCEL_COOLDOWN_MS < 1000)
    }

    @Test
    fun `parseJniOutput parses C2-2_6 extended format TOKENS TTFT text`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val parsed = runtime.parseJniOutput("42|15|{\"severity\":\"HIGH\"}")
        assertEquals(42, parsed.tokenCount)
        assertEquals(15L, parsed.ttftMs)
        assertEquals("{\"severity\":\"HIGH\"}", parsed.text)
    }

    @Test
    fun `parseJniOutput falls back to C2-2_5 format TOKENS text`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        // Only one pipe → C2-2.5 format (no TTFT)
        val parsed = runtime.parseJniOutput("42|{\"severity\":\"HIGH\"}")
        assertEquals(42, parsed.tokenCount)
        assertNull("TTFT should be null for old format", parsed.ttftMs)
        assertEquals("{\"severity\":\"HIGH\"}", parsed.text)
    }

    @Test
    fun `parseJniOutput rejects non-digit prefix`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val parsed = runtime.parseJniOutput("abc|some text")
        // Should fallback — abc is not all digits
        assertNull(parsed.ttftMs)
        assertEquals("abc|some text", parsed.text)
    }

    @Test
    fun `parseJniOutput rejects prefix longer than 6 digits`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        // 7-digit prefix → too long
        val parsed = runtime.parseJniOutput("1234567|text")
        assertEquals("1234567|text", parsed.text)
    }

    @Test
    fun `parseJniOutput handles empty output`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val parsed = runtime.parseJniOutput("")
        assertEquals("", parsed.text)
        assertNull(parsed.ttftMs)
    }

    @Test
    fun `parseJniOutput handles output with no pipe`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val parsed = runtime.parseJniOutput("just some text")
        assertEquals("just some text", parsed.text)
        assertNull(parsed.ttftMs)
    }

    @Test
    fun `parseJniOutput handles pipe in generated text`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        // Text contains | but it's after the two prefixes
        val parsed = runtime.parseJniOutput("10|5|text with | pipe in it")
        assertEquals(10, parsed.tokenCount)
        assertEquals(5L, parsed.ttftMs)
        assertEquals("text with | pipe in it", parsed.text)
    }

    @Test
    fun `parseJniOutput handles zero token count`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val parsed = runtime.parseJniOutput("0|0|")
        assertEquals(0, parsed.tokenCount)
        assertEquals(0L, parsed.ttftMs)
        assertEquals("", parsed.text)
    }

    @Test
    fun `unloaded runtime error mentions not available`() {
        val runtime = LlamaCppRuntime.createUnloaded()
        val result = runtime.runInference("test", InferenceConfig.SLOTS_DEFAULT)
        assertTrue("Should mention 'not available'", result.error!!.contains("not available"))
    }
}
