package com.cybersentinel.app.domain.llm

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ModelManager — manages model download, integrity verification, and lifecycle.
 *
 * Responsibilities:
 *  1. On-demand download (model is NEVER bundled in APK)
 *  2. SHA-256 integrity verification on download + periodic re-check
 *  3. Model state machine: NOT_DOWNLOADED → DOWNLOADING → READY → LOADED
 *  4. Storage budget check before download
 *  5. Kill switch integration (KILLED state disables model)
 *  6. Memory-safe load/unload (check RAM before loading)
 *
 * Design: Pure domain logic. Actual download I/O is abstracted via ModelDownloader interface.
 * This class is fully testable without Android context.
 *
 * Threading: All mutable state is accessed via @Volatile or synchronized.
 * Download operations run on the caller's coroutine/thread.
 */
@Singleton
class ModelManager @Inject constructor(
    private val downloader: ModelDownloader
) {
    // ══════════════════════════════════════════════════════════
    //  State
    // ══════════════════════════════════════════════════════════

    @Volatile
    private var currentState: ModelState = ModelState.NOT_DOWNLOADED

    @Volatile
    private var currentModelInfo: ModelInfo? = null

    @Volatile
    private var activeManifest: ModelManifest? = null

    @Volatile
    private var killSwitchActive: Boolean = false

    /** Get the current model state */
    fun getState(): ModelState = if (killSwitchActive) ModelState.KILLED else currentState

    /** Get info about the downloaded model (null if not downloaded) */
    fun getModelInfo(): ModelInfo? = currentModelInfo

    // ══════════════════════════════════════════════════════════
    //  Download + verification
    // ══════════════════════════════════════════════════════════

    /**
     * Download a model from the manifest.
     *
     * @param manifest Model manifest with download URL and expected hash
     * @param targetDir Directory to store the model file
     * @param onProgress Progress callback
     * @return ModelOperationResult
     */
    fun downloadModel(
        manifest: ModelManifest,
        targetDir: File,
        onProgress: ((DownloadProgress) -> Unit)? = null
    ): ModelOperationResult {
        if (killSwitchActive) {
            return ModelOperationResult.Failure("Model is disabled by kill switch")
        }

        // ARM64 gate: never download on non-arm64 devices
        if (manifest.requires64Bit && !LlamaCppRuntime.isArm64Device()) {
            return ModelOperationResult.Failure(
                "Model requires arm64-v8a but device does not support it"
            )
        }

        if (currentState == ModelState.DOWNLOADING) {
            return ModelOperationResult.Failure("Download already in progress")
        }

        // Check storage
        val availableSpace = targetDir.usableSpace
        if (availableSpace < manifest.fileSizeBytes + STORAGE_BUFFER_BYTES) {
            return ModelOperationResult.Failure(
                "Insufficient storage: need ${manifest.fileSizeBytes / 1_000_000}MB, " +
                    "available ${availableSpace / 1_000_000}MB"
            )
        }

        currentState = ModelState.DOWNLOADING
        activeManifest = manifest

        val targetFile = File(targetDir, "${manifest.modelId}.gguf")

        val downloadResult = try {
            onProgress?.invoke(
                DownloadProgress(manifest.modelId, manifest.fileSizeBytes, 0, DownloadState.DOWNLOADING)
            )

            downloader.download(manifest.downloadUrl, targetFile) { downloaded, total ->
                onProgress?.invoke(
                    DownloadProgress(manifest.modelId, total, downloaded, DownloadState.DOWNLOADING)
                )
            }
        } catch (e: Exception) {
            currentState = ModelState.NOT_DOWNLOADED
            return ModelOperationResult.Failure("Download failed: ${e.message}")
        }

        if (!downloadResult) {
            currentState = ModelState.NOT_DOWNLOADED
            return ModelOperationResult.Failure("Download failed")
        }

        // Verify integrity
        onProgress?.invoke(
            DownloadProgress(manifest.modelId, manifest.fileSizeBytes, manifest.fileSizeBytes, DownloadState.VERIFYING)
        )

        val verified = verifyIntegrity(targetFile, manifest.sha256)
        if (!verified) {
            targetFile.delete()
            currentState = ModelState.CORRUPTED
            return ModelOperationResult.Failure("Integrity check failed — SHA-256 mismatch")
        }

        // Success
        val modelInfo = ModelInfo(
            modelId = manifest.modelId,
            version = manifest.version,
            localPath = targetFile.absolutePath,
            fileSizeBytes = targetFile.length(),
            sha256 = manifest.sha256,
            downloadedAt = System.currentTimeMillis()
        )

        currentModelInfo = modelInfo
        currentState = ModelState.READY

        onProgress?.invoke(
            DownloadProgress(manifest.modelId, manifest.fileSizeBytes, manifest.fileSizeBytes, DownloadState.COMPLETED)
        )

        return ModelOperationResult.Success(modelInfo)
    }

    // ══════════════════════════════════════════════════════════
    //  Integrity verification
    // ══════════════════════════════════════════════════════════

    /**
     * Verify file integrity against expected SHA-256 hash.
     *
     * @param file The model file to verify
     * @param expectedSha256 Expected hash (lowercase hex)
     * @return true if file hash matches expected hash
     */
    fun verifyIntegrity(file: File, expectedSha256: String): Boolean {
        if (!file.exists() || !file.isFile) return false

        return try {
            val actualHash = computeSha256(file.inputStream())
            actualHash.equals(expectedSha256, ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Compute SHA-256 hash of an input stream.
     * Reads in chunks to handle large files without OOM.
     */
    internal fun computeSha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(HASH_BUFFER_SIZE)
        input.use { stream ->
            var bytesRead = stream.read(buffer)
            while (bytesRead != -1) {
                digest.update(buffer, 0, bytesRead)
                bytesRead = stream.read(buffer)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    // ══════════════════════════════════════════════════════════
    //  Lifecycle
    // ══════════════════════════════════════════════════════════

    /**
     * Mark model as loaded (called by LlmRuntime after loading into memory).
     */
    fun markLoaded() {
        if (currentState == ModelState.READY) {
            currentState = ModelState.LOADED
        }
    }

    /**
     * Mark model as unloaded (back to READY state).
     */
    fun markUnloaded() {
        if (currentState == ModelState.LOADED) {
            currentState = ModelState.READY
        }
    }

    /**
     * Delete the downloaded model and reset state.
     */
    fun deleteModel() {
        val info = currentModelInfo
        if (info != null) {
            File(info.localPath).delete()
        }
        currentModelInfo = null
        currentState = ModelState.NOT_DOWNLOADED
        activeManifest = null
    }

    // ══════════════════════════════════════════════════════════
    //  Kill switch
    // ══════════════════════════════════════════════════════════

    /**
     * Activate kill switch — model becomes unusable.
     * Called from remote config or emergency flag.
     */
    fun activateKillSwitch() {
        killSwitchActive = true
    }

    /**
     * Deactivate kill switch — model can be used again (if READY/LOADED).
     */
    fun deactivateKillSwitch() {
        killSwitchActive = false
    }

    fun isKillSwitchActive(): Boolean = killSwitchActive

    // ══════════════════════════════════════════════════════════
    //  Re-verification (periodic integrity check)
    // ══════════════════════════════════════════════════════════

    /**
     * Re-verify the downloaded model's integrity.
     * Call periodically or before critical operations.
     *
     * @return true if model is intact, false if corrupted/missing
     */
    fun reverifyIntegrity(): Boolean {
        val info = currentModelInfo ?: return false
        val manifest = activeManifest ?: return false
        val file = File(info.localPath)

        val intact = verifyIntegrity(file, manifest.sha256)
        if (!intact) {
            currentState = ModelState.CORRUPTED
        }
        return intact
    }

    // ══════════════════════════════════════════════════════════
    //  Constants
    // ══════════════════════════════════════════════════════════

    companion object {
        /** Extra storage buffer beyond model size (50 MB) */
        const val STORAGE_BUFFER_BYTES = 50L * 1024 * 1024

        /** Buffer size for SHA-256 computation (8 KB) */
        const val HASH_BUFFER_SIZE = 8192

        /** HMAC algorithm for manifest signature verification */
        const val HMAC_ALGORITHM = "HmacSHA256"
    }

    // ══════════════════════════════════════════════════════════
    //  Manifest signature verification
    // ══════════════════════════════════════════════════════════

    /**
     * Verify a model manifest's HMAC signature.
     *
     * The signature covers: modelId|version|sha256|downloadUrl
     * Key is provided by the server / embedded in the app (for MVP).
     *
     * ⚠️ THREAT MODEL NOTE (C2-2.5):
     *   HMAC is a symmetric scheme — the key is embedded in the APK and can be
     *   extracted by an attacker who decompiles the app. This means HMAC protects
     *   against ACCIDENTAL tampering (CDN corruption, network bit-flip, misconfigured
     *   proxy), but NOT against a motivated attacker who can sign their own manifest.
     *
     *   For production hardening, migrate to ASYMMETRIC signature verification:
     *     - Server signs manifest with a private key (Ed25519 or ECDSA P-256)
     *     - App verifies with pinned public key (cannot be used to forge signatures)
     *     - Combined with pinned TLS + SHA-256 file hash, this forms a complete
     *       supply-chain integrity chain.
     *
     *   The current HMAC + SHA-256 file hash is still valuable:
     *     - SHA-256 of the model file itself is the hard integrity gate
     *     - HMAC of the manifest prevents casual URL/hash swaps
     *     - Together they block most realistic attack vectors for an on-device MVP
     *
     * @param manifest The manifest to verify
     * @param signature HMAC-SHA256 signature (hex string)
     * @param key HMAC key
     * @return true if signature is valid
     */
    fun verifyManifestSignature(
        manifest: ModelManifest,
        signature: String,
        key: ByteArray
    ): Boolean {
        return try {
            val payload = "${manifest.modelId}|${manifest.version}|${manifest.sha256}|${manifest.downloadUrl}"
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
            val expectedSignature = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            expectedSignature.equals(signature, ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if the current device supports the model's ABI requirements.
     * Convenience wrapper around LlamaCppRuntime.isArm64Device().
     */
    fun isDeviceCompatible(manifest: ModelManifest): Boolean {
        return !manifest.requires64Bit || LlamaCppRuntime.isArm64Device()
    }
}

// ══════════════════════════════════════════════════════════
//  Abstraction for download I/O
// ══════════════════════════════════════════════════════════

/**
 * Interface for model file download. Abstracted for testability.
 *
 * Implementations:
 *  - HttpModelDownloader (production): OkHttp/HttpURLConnection download
 *  - FakeModelDownloader (test): writes fixture bytes
 */
interface ModelDownloader {
    /**
     * Download a file from URL to target location.
     *
     * @param url Source URL
     * @param target Target file
     * @param onProgress Progress callback (downloaded bytes, total bytes)
     * @return true if download completed successfully
     */
    fun download(
        url: String,
        target: File,
        onProgress: ((downloaded: Long, total: Long) -> Unit)? = null
    ): Boolean
}

/**
 * Result of a model operation (download, verify, etc.)
 */
sealed class ModelOperationResult {
    data class Success(val modelInfo: ModelInfo) : ModelOperationResult()
    data class Failure(val error: String) : ModelOperationResult()

    val isSuccess: Boolean get() = this is Success
}
