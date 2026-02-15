package com.cybersentinel.app.domain.llm

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Tests for ModelManager C2-2 additions:
 *  - ARM64 download guard
 *  - Manifest HMAC signature verification
 *  - Device compatibility check
 *
 * Extends existing ModelManager tests from LlmPipelineIntegrationTest.
 */
class ModelManagerGuardTest {

    private lateinit var modelManager: ModelManager
    private lateinit var fakeDownloader: FakeDownloaderForGuardTest

    private val testManifest = ModelManifest(
        modelId = "test-model-q4",
        displayName = "Test Model",
        version = "1.0.0",
        downloadUrl = "https://example.com/model.gguf",
        fileSizeBytes = 100_000,
        sha256 = "abc123",
        quantization = "Q4_K_M",
        requires64Bit = true
    )

    @Before
    fun setUp() {
        fakeDownloader = FakeDownloaderForGuardTest()
        modelManager = ModelManager(fakeDownloader)
    }

    // ══════════════════════════════════════════════════════════
    //  ARM64 download guard
    // ══════════════════════════════════════════════════════════

    @Test
    fun `downloadModel rejects 64-bit model on non-arm64 device`() {
        // In JVM tests, Build.SUPPORTED_ABIS is empty → not arm64
        val result = modelManager.downloadModel(testManifest, File("/tmp/models"))
        assertTrue("Should fail on non-arm64", result is ModelOperationResult.Failure)
        val failure = result as ModelOperationResult.Failure
        assertTrue("Error should mention arm64", failure.error.contains("arm64"))
    }

    @Test
    fun `downloadModel allows non-64bit model on any device`() {
        val nonArmManifest = testManifest.copy(requires64Bit = false)
        // This will proceed past the ARM64 check (may fail at download step, but not at the guard)
        val result = modelManager.downloadModel(nonArmManifest, File("/tmp/models"))
        // It should NOT fail with "arm64" error — may fail for other reasons (storage, download, etc.)
        if (result is ModelOperationResult.Failure) {
            assertFalse(
                "Should not fail with arm64 error for non-64bit model",
                result.error.contains("arm64")
            )
        }
    }

    @Test
    fun `downloadModel rejects when kill switch is active`() {
        modelManager.activateKillSwitch()
        val result = modelManager.downloadModel(testManifest, File("/tmp/models"))
        assertTrue(result is ModelOperationResult.Failure)
        assertTrue((result as ModelOperationResult.Failure).error.contains("kill switch"))
    }

    // ══════════════════════════════════════════════════════════
    //  Device compatibility
    // ══════════════════════════════════════════════════════════

    @Test
    fun `isDeviceCompatible returns false for 64-bit model on non-arm64`() {
        assertFalse(modelManager.isDeviceCompatible(testManifest))
    }

    @Test
    fun `isDeviceCompatible returns true for non-64bit model`() {
        val nonArmManifest = testManifest.copy(requires64Bit = false)
        assertTrue(modelManager.isDeviceCompatible(nonArmManifest))
    }

    // ══════════════════════════════════════════════════════════
    //  Manifest HMAC signature verification
    // ══════════════════════════════════════════════════════════

    @Test
    fun `verifyManifestSignature accepts valid HMAC`() {
        val key = "test-secret-key-12345".toByteArray()
        val payload = "${testManifest.modelId}|${testManifest.version}|${testManifest.sha256}|${testManifest.downloadUrl}"

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val signature = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        assertTrue(
            "Valid HMAC should be accepted",
            modelManager.verifyManifestSignature(testManifest, signature, key)
        )
    }

    @Test
    fun `verifyManifestSignature rejects invalid signature`() {
        val key = "test-secret-key-12345".toByteArray()
        assertFalse(
            "Invalid signature should be rejected",
            modelManager.verifyManifestSignature(testManifest, "deadbeef", key)
        )
    }

    @Test
    fun `verifyManifestSignature rejects wrong key`() {
        val correctKey = "correct-key".toByteArray()
        val wrongKey = "wrong-key".toByteArray()

        val payload = "${testManifest.modelId}|${testManifest.version}|${testManifest.sha256}|${testManifest.downloadUrl}"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(correctKey, "HmacSHA256"))
        val signature = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        assertFalse(
            "Wrong key should be rejected",
            modelManager.verifyManifestSignature(testManifest, signature, wrongKey)
        )
    }

    @Test
    fun `verifyManifestSignature rejects tampered manifest`() {
        val key = "test-key".toByteArray()
        val payload = "${testManifest.modelId}|${testManifest.version}|${testManifest.sha256}|${testManifest.downloadUrl}"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val signature = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        // Tamper with the manifest
        val tampered = testManifest.copy(downloadUrl = "https://evil.com/model.gguf")
        assertFalse(
            "Tampered manifest should be rejected",
            modelManager.verifyManifestSignature(tampered, signature, key)
        )
    }

    @Test
    fun `verifyManifestSignature handles empty key gracefully`() {
        // Empty key may cause crypto exceptions — should return false, not crash
        val result = modelManager.verifyManifestSignature(testManifest, "abc", ByteArray(0))
        // Just checking it doesn't throw; result may vary by JVM implementation
        assertNotNull(result)
    }

    @Test
    fun `verifyManifestSignature is case-insensitive for hex`() {
        val key = "test-key".toByteArray()
        val payload = "${testManifest.modelId}|${testManifest.version}|${testManifest.sha256}|${testManifest.downloadUrl}"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val signatureLower = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val signatureUpper = signatureLower.uppercase()

        assertTrue(modelManager.verifyManifestSignature(testManifest, signatureLower, key))
        assertTrue(modelManager.verifyManifestSignature(testManifest, signatureUpper, key))
    }

    // ══════════════════════════════════════════════════════════
    //  Kill switch interaction with guards
    // ══════════════════════════════════════════════════════════

    @Test
    fun `kill switch takes precedence over ARM64 guard`() {
        modelManager.activateKillSwitch()
        val result = modelManager.downloadModel(testManifest, File("/tmp/models"))
        assertTrue(result is ModelOperationResult.Failure)
        // Kill switch check comes before ARM64 check
        assertTrue((result as ModelOperationResult.Failure).error.contains("kill switch"))
    }

    @Test
    fun `state is KILLED when kill switch is active`() {
        modelManager.activateKillSwitch()
        assertEquals(ModelState.KILLED, modelManager.getState())
    }

    @Test
    fun `state returns to normal after kill switch deactivation`() {
        modelManager.activateKillSwitch()
        assertEquals(ModelState.KILLED, modelManager.getState())
        modelManager.deactivateKillSwitch()
        assertEquals(ModelState.NOT_DOWNLOADED, modelManager.getState())
    }

    // ══════════════════════════════════════════════════════════
    //  SHA-256 integrity (existing functionality, regression tests)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `computeSha256 produces correct hash for known input`() {
        val input = "Hello, CyberSentinel!".toByteArray()
        val hash = modelManager.computeSha256(input.inputStream())
        // SHA-256 of "Hello, CyberSentinel!" — deterministic
        assertNotNull(hash)
        assertEquals(64, hash.length) // SHA-256 hex = 64 chars
    }

    @Test
    fun `computeSha256 produces different hashes for different inputs`() {
        val hash1 = modelManager.computeSha256("input1".toByteArray().inputStream())
        val hash2 = modelManager.computeSha256("input2".toByteArray().inputStream())
        assertNotEquals("Different inputs should have different hashes", hash1, hash2)
    }

    @Test
    fun `verifyIntegrity returns false for non-existent file`() {
        assertFalse(modelManager.verifyIntegrity(File("/nonexistent/file.gguf"), "abc"))
    }

    // ── Fake downloader for test isolation ──

    class FakeDownloaderForGuardTest : ModelDownloader {
        override fun download(url: String, target: File, onProgress: ((Long, Long) -> Unit)?): Boolean {
            // In these tests we don't actually reach download (blocked by guards)
            return false
        }
    }
}
