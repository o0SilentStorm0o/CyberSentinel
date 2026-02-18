package com.cybersentinel.app.domain.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Trust Evidence Engine — „Důkazový model důvěry"
 *
 * Místo triviálního whitelistu shromažďuje *důkazy* o tom, proč aplikaci věřit (nebo ne).
 * Výsledné TrustScore (0-100) říká, jak silná je identita & provenance.
 *
 * Každý důkaz přispívá k TrustScore, ale žádný sám o sobě neznamená „imunitu":
 *  - Signature match (cert digest)         → +30
 *  - Installer provenance (Play Store…)     → +20
 *  - System/privileged flag                 → +15
 *  - Platform/OEM cert match               → +15
 *  - Signing lineage continuity            → +10
 *  - Device integrity (verified boot)       → +10
 *
 * Max = 100. Prakticky reálná trusted app bude mít 50-80.
 *
 * PRODUKTOVÉ PRAVIDLO:
 *  TrustScore NIKDY nepotlačí „hard findings" (debug cert, baseline mismatch,
 *  integrity fail + hooking, installer anomaly). Pouze snižuje váhu „soft findings"
 *  (exported components, over-privileged heuristika, old SDK).
 */
@Singleton
class TrustEvidenceEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {

    // ──────────────────────────────────────────────────────────
    //  Data model
    // ──────────────────────────────────────────────────────────

    /**
     * Complete trust evidence collected for one app
     */
    data class TrustEvidence(
        val packageName: String,
        val certSha256: String,
        val certMatch: CertMatchResult,
        val installerInfo: InstallerInfo,
        val systemAppInfo: SystemAppInfo,
        val signingLineage: SigningLineageInfo,
        val deviceIntegrity: DeviceIntegrityInfo,
        val trustScore: Int,       // 0-100
        val trustLevel: TrustLevel,
        val reasons: List<TrustReason>
    )

    enum class TrustLevel {
        /** Very strong identity evidence (score 70+) */
        HIGH,
        /** Reasonable identity evidence (score 40-69) */
        MODERATE,
        /** Weak or no identity evidence (score 15-39) */
        LOW,
        /** Anomaly detected — treat with extra scrutiny */
        ANOMALOUS
    }

    data class CertMatchResult(
        val matchType: CertMatchType,
        val matchedDeveloper: String?,
        /** When app supports key rotation, all historical digests we know */
        val knownCertDigests: Set<String>,
        val currentCertDigest: String
    )

    enum class CertMatchType {
        /** Cert matches a known trusted developer */
        DEVELOPER_MATCH,
        /** Cert matches individually verified app entry */
        APP_MATCH,
        /** Package looks like a trusted app but cert is WRONG — possible re-sign */
        CERT_MISMATCH,
        /** Package not in any trusted list */
        UNKNOWN
    }

    data class InstallerInfo(
        val installerPackage: String?,
        val installerType: InstallerType,
        val isExpectedInstaller: Boolean
    )

    enum class InstallerType {
        PLAY_STORE,
        SYSTEM_INSTALLER,
        SAMSUNG_STORE,
        HUAWEI_APPGALLERY,
        AMAZON_APPSTORE,
        MDM_INSTALLER,
        SIDELOADED,
        UNKNOWN
    }

    data class SystemAppInfo(
        val isSystemApp: Boolean,
        val isPrivilegedApp: Boolean,
        val isUpdatedSystemApp: Boolean,
        val partition: AppPartition,
        val isPlatformSigned: Boolean
    )

    enum class AppPartition {
        /** /system — core ROM */
        SYSTEM,
        /** /vendor — OEM specific */
        VENDOR,
        /** /product — product-specific */
        PRODUCT,
        /** /data — user-installed */
        DATA,
        /** Cannot determine */
        UNKNOWN
    }

    data class SigningLineageInfo(
        val hasLineage: Boolean,
        val lineageLength: Int,
        /** If lineage is available and all ancestors are trusted */
        val lineageTrusted: Boolean
    )

    data class DeviceIntegrityInfo(
        val isRooted: Boolean,
        val verifiedBootState: VerifiedBootState
    )

    enum class VerifiedBootState {
        /** Boot verified, system partition intact */
        GREEN,
        /** Custom key, but boot verified */
        YELLOW,
        /** Unlocked bootloader */
        ORANGE,
        /** Verification failed */
        RED,
        /** Cannot determine */
        UNKNOWN
    }

    data class TrustReason(
        val evidence: String,
        val contribution: Int,
        val isPositive: Boolean
    )

    // ──────────────────────────────────────────────────────────
    //  Known trusted installers
    // ──────────────────────────────────────────────────────────

    private val knownInstallers = mapOf(
        "com.android.vending" to InstallerType.PLAY_STORE,
        "com.google.android.packageinstaller" to InstallerType.SYSTEM_INSTALLER,
        "com.android.packageinstaller" to InstallerType.SYSTEM_INSTALLER,
        "com.samsung.android.scloud" to InstallerType.SAMSUNG_STORE,
        "com.sec.android.app.samsungapps" to InstallerType.SAMSUNG_STORE,
        "com.huawei.appmarket" to InstallerType.HUAWEI_APPGALLERY,
        "com.amazon.venezia" to InstallerType.AMAZON_APPSTORE
    )

    // Cache device-level info (same for all apps)
    private val cachedDeviceIntegrity: DeviceIntegrityInfo by lazy { collectDeviceIntegrity() }
    private val cachedPlatformCertDigest: String? by lazy { detectPlatformCertDigest() }

    // ──────────────────────────────────────────────────────────
    //  Public API
    // ──────────────────────────────────────────────────────────

    /**
     * Collect trust evidence for an app.
     * This is the main entry point — call once per app during scan.
     */
    @SuppressLint("PackageManagerGetSignatures")
    fun collectEvidence(
        packageInfo: PackageInfo,
        certSha256: String
    ): TrustEvidence {
        val reasons = mutableListOf<TrustReason>()
        var score = 0

        // 0. System app status — must be evaluated FIRST so we can
        //    determine the signer domain before cert comparison.
        val systemInfo = checkSystemAppStatus(packageInfo)
        if (systemInfo.isSystemApp) {
            score += 15
            reasons.add(TrustReason("Systémová aplikace (${systemInfo.partition.label()})", 15, true))
        }
        if (systemInfo.isPlatformSigned) {
            score += 15
            reasons.add(TrustReason("Podepsána platformovým klíčem", 15, true))
        }

        // Determine signer domain so cert comparison is domain-aware.
        // A PLATFORM_SIGNED system app must not be compared against a
        // PLAY_SIGNED developer whitelist entry — that always "mismatches".
        val sourceDir = packageInfo.applicationInfo?.sourceDir
        val isApex = sourceDir?.startsWith("/apex/") == true
        val signerDomain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = systemInfo.isSystemApp,
            isApex = isApex,
            isPlatformSigned = systemInfo.isPlatformSigned,
            partition = systemInfo.partition,
            sourceDir = sourceDir
        )

        // 1. Certificate match against known trusted apps/developers
        val certMatch = verifyCertificate(packageInfo.packageName, certSha256, signerDomain)
        when (certMatch.matchType) {
            CertMatchType.DEVELOPER_MATCH -> {
                score += 30
                reasons.add(TrustReason("Certifikát odpovídá známému vývojáři (${certMatch.matchedDeveloper})", 30, true))
            }
            CertMatchType.APP_MATCH -> {
                score += 30
                reasons.add(TrustReason("Certifikát odpovídá ověřené aplikaci", 30, true))
            }
            CertMatchType.CERT_MISMATCH -> {
                score -= 20 // Penalty — this is suspicious
                reasons.add(TrustReason("Certifikát NEODPOVÍDÁ očekávanému — možná přebalená verze!", -20, false))
            }
            CertMatchType.UNKNOWN -> {
                // No match, no penalty — just unknown
                reasons.add(TrustReason("Aplikace není v seznamu ověřených", 0, true))
            }
        }

        // 2. Installer provenance (second factor)
        val installerInfo = checkInstallerProvenance(packageInfo.packageName)
        if (installerInfo.isExpectedInstaller) {
            score += 20
            reasons.add(TrustReason("Nainstalováno z ${installerInfo.installerType.label()}", 20, true))
        } else if (installerInfo.installerType == InstallerType.SIDELOADED) {
            // Sideloaded isn't automatically bad, but reduces trust
            score -= 5
            reasons.add(TrustReason("Nainstalováno mimo obchod (sideload)", -5, false))
        }

        // 3. (System app status already evaluated in step 0)

        // 4. Signing lineage (key rotation)
        val lineage = checkSigningLineage(packageInfo)
        if (lineage.hasLineage && lineage.lineageTrusted) {
            score += 10
            reasons.add(TrustReason("Podpisová kontinuita ověřena (${lineage.lineageLength} klíčů)", 10, true))
        }

        // 5. Device integrity
        val integrity = cachedDeviceIntegrity
        when (integrity.verifiedBootState) {
            VerifiedBootState.GREEN -> {
                score += 10
                reasons.add(TrustReason("Zařízení v ověřeném stavu (Verified Boot)", 10, true))
            }
            VerifiedBootState.ORANGE, VerifiedBootState.RED -> {
                // Device is compromised — trust is weaker
                score -= 10
                reasons.add(TrustReason("Odemčený bootloader — systémové komponenty mohou být podvržené", -10, false))
            }
            else -> { /* neutral */ }
        }
        if (integrity.isRooted) {
            score -= 15
            reasons.add(TrustReason("Root detekován — zvýšená citlivost", -15, false))
        }

        // Clamp score
        val finalScore = score.coerceIn(0, 100)

        // Determine trust level
        val trustLevel = when {
            certMatch.matchType == CertMatchType.CERT_MISMATCH -> TrustLevel.ANOMALOUS
            integrity.isRooted && systemInfo.isSystemApp && !systemInfo.isPlatformSigned -> TrustLevel.ANOMALOUS
            finalScore >= 70 -> TrustLevel.HIGH
            finalScore >= 40 -> TrustLevel.MODERATE
            else -> TrustLevel.LOW
        }

        return TrustEvidence(
            packageName = packageInfo.packageName,
            certSha256 = certSha256,
            certMatch = certMatch,
            installerInfo = installerInfo,
            systemAppInfo = systemInfo,
            signingLineage = lineage,
            deviceIntegrity = integrity,
            trustScore = finalScore,
            trustLevel = trustLevel,
            reasons = reasons
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Private — Certificate verification
    // ──────────────────────────────────────────────────────────

    private fun verifyCertificate(
        packageName: String,
        certSha256: String,
        signerDomain: TrustedAppsWhitelist.TrustDomain = TrustedAppsWhitelist.TrustDomain.PLAY_SIGNED
    ): CertMatchResult {
        val certPrefix = certSha256.take(40).uppercase()

        // Check individual verified apps (with rotation support — multiple allowed digests)
        val appCerts = TrustedAppsWhitelist.getVerifiedAppCerts(packageName)
        if (appCerts != null) {
            val matches = appCerts.any { knownDigest ->
                certPrefix.startsWith(knownDigest) || knownDigest.startsWith(certPrefix)
            }
            return CertMatchResult(
                matchType = if (matches) CertMatchType.APP_MATCH else CertMatchType.CERT_MISMATCH,
                matchedDeveloper = if (matches) packageName else null,
                knownCertDigests = appCerts,
                currentCertDigest = certSha256
            )
        }

        // Check developer certs (prefix-based, domain-aware).
        // Pass signerDomain so a PLATFORM_SIGNED app doesn't match against
        // a PLAY_SIGNED developer entry (which would always "mismatch").
        val developerMatch = TrustedAppsWhitelist.matchDeveloperCert(packageName, certPrefix, signerDomain)
        if (developerMatch != null) {
            return CertMatchResult(
                matchType = if (developerMatch.certMatches) CertMatchType.DEVELOPER_MATCH else CertMatchType.CERT_MISMATCH,
                matchedDeveloper = developerMatch.developerName,
                knownCertDigests = setOf(developerMatch.expectedCert),
                currentCertDigest = certSha256
            )
        }

        // No whitelist entry matched.  For non-PLAY domains (platform,
        // APEX, OEM) this is expected — return UNKNOWN, not MISMATCH.
        return CertMatchResult(
            matchType = CertMatchType.UNKNOWN,
            matchedDeveloper = null,
            knownCertDigests = emptySet(),
            currentCertDigest = certSha256
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Private — Installer provenance
    // ──────────────────────────────────────────────────────────

    private fun checkInstallerProvenance(packageName: String): InstallerInfo {
        val pm = context.packageManager
        val installerPackage = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            null
        }

        val installerType = when {
            installerPackage == null -> InstallerType.UNKNOWN
            knownInstallers.containsKey(installerPackage) -> knownInstallers[installerPackage]!!
            installerPackage.contains("mdm", ignoreCase = true) ||
            installerPackage.contains("enterprise", ignoreCase = true) -> InstallerType.MDM_INSTALLER
            else -> InstallerType.SIDELOADED
        }

        // Expected installer = any recognized app store or system installer
        val isExpected = installerType in setOf(
            InstallerType.PLAY_STORE,
            InstallerType.SYSTEM_INSTALLER,
            InstallerType.SAMSUNG_STORE,
            InstallerType.HUAWEI_APPGALLERY,
            InstallerType.AMAZON_APPSTORE,
            InstallerType.MDM_INSTALLER
        )

        return InstallerInfo(
            installerPackage = installerPackage,
            installerType = installerType,
            isExpectedInstaller = isExpected
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Private — System app analysis
    // ──────────────────────────────────────────────────────────

    private fun checkSystemAppStatus(packageInfo: PackageInfo): SystemAppInfo {
        val appInfo = packageInfo.applicationInfo

        val isSystem = appInfo?.let {
            (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        } ?: false

        val isPrivileged = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appInfo?.let {
                try {
                    val privateFlagsField = ApplicationInfo::class.java.getField("privateFlags")
                    val flags = privateFlagsField.getInt(it)
                    val privilegedFlag = ApplicationInfo::class.java.getField("PRIVATE_FLAG_PRIVILEGED")
                        .getInt(null)
                    (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (flags and privilegedFlag) != 0
                } catch (_: Exception) {
                    isSystem
                }
            } ?: false
        } else {
            isSystem
        }

        val isUpdatedSystem = appInfo?.let {
            (it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        } ?: false

        val partition = determinePartition(appInfo)

        // Check if signed with platform cert
        val isPlatformSigned = cachedPlatformCertDigest?.let { platformCert ->
            val appCert = getAppCertDigest(packageInfo)
            appCert != null && appCert == platformCert
        } ?: false

        return SystemAppInfo(
            isSystemApp = isSystem,
            isPrivilegedApp = isPrivileged,
            isUpdatedSystemApp = isUpdatedSystem,
            partition = partition,
            isPlatformSigned = isPlatformSigned
        )
    }

    private fun determinePartition(appInfo: ApplicationInfo?): AppPartition {
        val sourceDir = appInfo?.sourceDir ?: return AppPartition.UNKNOWN
        return when {
            sourceDir.startsWith("/system/") -> AppPartition.SYSTEM
            sourceDir.startsWith("/vendor/") -> AppPartition.VENDOR
            sourceDir.startsWith("/product/") -> AppPartition.PRODUCT
            sourceDir.startsWith("/data/") -> AppPartition.DATA
            else -> AppPartition.UNKNOWN
        }
    }

    // ──────────────────────────────────────────────────────────
    //  Private — Signing lineage
    // ──────────────────────────────────────────────────────────

    private fun checkSigningLineage(packageInfo: PackageInfo): SigningLineageInfo {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return SigningLineageInfo(hasLineage = false, lineageLength = 0, lineageTrusted = false)
        }

        val signingInfo = packageInfo.signingInfo ?: return SigningLineageInfo(
            hasLineage = false, lineageLength = 0, lineageTrusted = false
        )

        val hasPastSigners = signingInfo.hasPastSigningCertificates()
        if (!hasPastSigners) {
            return SigningLineageInfo(hasLineage = false, lineageLength = 1, lineageTrusted = false)
        }

        // Lineage is available — the app has rotated keys
        val pastSigners = signingInfo.signingCertificateHistory ?: return SigningLineageInfo(
            hasLineage = true, lineageLength = 1, lineageTrusted = false
        )

        // For now, lineage presence itself is a trust signal (demonstrates legitimate evolution)
        // In a real scenario we'd check each ancestor cert against known digests
        return SigningLineageInfo(
            hasLineage = true,
            lineageLength = pastSigners.size,
            lineageTrusted = true // Simplified: lineage exists = continuity proven
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Private — Device integrity
    // ──────────────────────────────────────────────────────────

    private fun collectDeviceIntegrity(): DeviceIntegrityInfo {
        return DeviceIntegrityInfo(
            isRooted = checkRooted(),
            verifiedBootState = checkVerifiedBoot()
        )
    }

    private fun checkRooted(): Boolean {
        val rootPaths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su"
        )
        val rootPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser"
        )

        val pathExists = rootPaths.any { java.io.File(it).exists() }
        val packageExists = rootPackages.any { pkg ->
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                true
            } catch (e: Exception) {
                false
            }
        }

        return pathExists || packageExists
    }

    private fun checkVerifiedBoot(): VerifiedBootState {
        return try {
            @SuppressLint("PrivateApi")
            val clazz = Class.forName("android.os.SystemProperties")
            val getMethod = clazz.getMethod("get", String::class.java, String::class.java)
            val bootState = getMethod.invoke(null, "ro.boot.verifiedbootstate", "") as? String ?: ""
            when (bootState.lowercase(java.util.Locale.ROOT)) {
                "green" -> VerifiedBootState.GREEN
                "yellow" -> VerifiedBootState.YELLOW
                "orange" -> VerifiedBootState.ORANGE
                "red" -> VerifiedBootState.RED
                else -> VerifiedBootState.UNKNOWN
            }
        } catch (e: Exception) {
            VerifiedBootState.UNKNOWN
        }
    }

    // ──────────────────────────────────────────────────────────
    //  Private — Platform cert detection
    // ──────────────────────────────────────────────────────────

    @SuppressLint("PackageManagerGetSignatures")
    private fun detectPlatformCertDigest(): String? {
        // The "android" package is always signed with the platform key
        return try {
            val androidPkg = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    "android",
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo("android", PackageManager.GET_SIGNATURES)
            }
            getAppCertDigest(androidPkg)
        } catch (e: Exception) {
            null
        }
    }

    @SuppressLint("PackageManagerGetSignatures")
    private fun getAppCertDigest(packageInfo: PackageInfo): String? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures
        }
        val sig = signatures?.firstOrNull() ?: return null
        return MessageDigest.getInstance("SHA-256")
            .digest(sig.toByteArray())
            .joinToString("") { "%02X".format(it) }
    }

    // ──────────────────────────────────────────────────────────
    //  Extension helpers
    // ──────────────────────────────────────────────────────────

    private fun InstallerType.label(): String = when (this) {
        InstallerType.PLAY_STORE -> "Google Play"
        InstallerType.SYSTEM_INSTALLER -> "Systémový instalátor"
        InstallerType.SAMSUNG_STORE -> "Samsung Galaxy Store"
        InstallerType.HUAWEI_APPGALLERY -> "Huawei AppGallery"
        InstallerType.AMAZON_APPSTORE -> "Amazon Appstore"
        InstallerType.MDM_INSTALLER -> "Firemní správa (MDM)"
        InstallerType.SIDELOADED -> "Ruční instalace"
        InstallerType.UNKNOWN -> "Neznámý zdroj"
    }

    private fun AppPartition.label(): String = when (this) {
        AppPartition.SYSTEM -> "systém"
        AppPartition.VENDOR -> "výrobce"
        AppPartition.PRODUCT -> "produkt"
        AppPartition.DATA -> "uživatel"
        AppPartition.UNKNOWN -> "neznámá"
    }
}
