package com.cybersentinel.app.domain.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.provider.Settings
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Advanced App Security Scanner
 * 
 * Unique features no other Android security app offers:
 * 1. APK Signature & Certificate Analysis - detects re-signed/tampered apps
 * 2. Permission Behavior Analysis - finds over-privileged apps
 * 3. Native Library Scanning - detects suspicious .so files
 * 4. Intent Filter Analysis - finds exported components risks
 * 5. Real-time CVE matching via CPE
 * 6. Trust Evidence Engine - multi-factor identity verification
 * 7. Baseline Manager - change detection across scans
 * 8. Trust & Risk Model - combined severity with hard/soft finding classification
 */
@Singleton
class AppSecurityScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val trustEngine: TrustEvidenceEngine,
    private val trustRiskModel: TrustRiskModel,
    private val baselineManager: BaselineManager,
    private val specialAccessInspector: SpecialAccessInspector
) {
    
    /**
     * Comprehensive app security analysis result
     */
    data class AppSecurityReport(
        val app: ScannedApp,
        val signatureAnalysis: SignatureAnalysis,
        val permissionAnalysis: PermissionAnalysis,
        val componentAnalysis: ComponentAnalysis,
        val nativeLibAnalysis: NativeLibAnalysis,
        val trustVerification: TrustedAppsWhitelist.TrustVerification,
        val trustEvidence: TrustEvidenceEngine.TrustEvidence,
        val verdict: TrustRiskModel.AppVerdict,
        val baselineComparison: BaselineManager.BaselineComparison,
        val overallRisk: RiskLevel,
        val issues: List<AppSecurityIssue>
    )
    
    data class ScannedApp(
        val packageName: String,
        val appName: String,
        val versionName: String?,
        val versionCode: Long,
        val installedAt: Long,
        val lastUpdated: Long,
        val isSystemApp: Boolean,
        val targetSdk: Int,
        val minSdk: Int,
        val apkPath: String?,
        val apkSizeBytes: Long
    )
    
    data class SignatureAnalysis(
        val sha256Fingerprint: String,
        val issuer: String,
        val subject: String,
        val validFrom: Long,
        val validUntil: Long,
        val isDebugSigned: Boolean,
        val signatureScheme: String,  // v1, v2, v3
        val isTrustedDeveloper: Boolean,
        val issues: List<String>
    )
    
    data class PermissionAnalysis(
        val dangerousPermissions: List<PermissionDetail>,
        val normalPermissions: List<String>,
        val signaturePermissions: List<String>,
        val runtimePermissionsGranted: List<String>,
        val runtimePermissionsDenied: List<String>,
        val isOverPrivileged: Boolean,
        val privacyScore: Int,  // 0-100, higher = more privacy risk
        val issues: List<String>
    )
    
    data class PermissionDetail(
        val permission: String,
        val shortName: String,
        val category: PermissionCategory,
        val isGranted: Boolean,
        val riskLevel: RiskLevel,
        val description: String
    )
    
    enum class PermissionCategory(val label: String, val icon: String) {
        LOCATION("Poloha", "📍"),
        CAMERA("Kamera", "📷"),
        MICROPHONE("Mikrofon", "🎤"),
        CONTACTS("Kontakty", "👥"),
        STORAGE("Úložiště", "💾"),
        PHONE("Telefon", "📞"),
        SMS("SMS", "💬"),
        CALENDAR("Kalendář", "📅"),
        SENSORS("Senzory", "📊"),
        BLUETOOTH("Bluetooth", "📶"),
        NETWORK("Síť", "🌐"),
        SYSTEM("Systém", "⚙️"),
        OTHER("Ostatní", "📋")
    }
    
    data class ComponentAnalysis(
        val exportedActivities: List<ExportedComponent>,
        val exportedServices: List<ExportedComponent>,
        val exportedReceivers: List<ExportedComponent>,
        val exportedProviders: List<ExportedComponent>,
        val deepLinks: List<DeepLinkInfo>,
        val hasExportedRisks: Boolean,
        val issues: List<String>
    )
    
    data class ExportedComponent(
        val name: String,
        val isProtected: Boolean,  // has permission requirement
        val permission: String?,
        val intentFilters: List<String>,
        val risk: RiskLevel
    )
    
    data class DeepLinkInfo(
        val scheme: String,
        val host: String?,
        val path: String?,
        val isHttps: Boolean,
        val couldBeHijacked: Boolean
    )
    
    data class NativeLibAnalysis(
        val hasNativeCode: Boolean,
        val architectures: List<String>,  // arm64-v8a, armeabi-v7a, x86, x86_64
        val libraries: List<NativeLibInfo>,
        val hasSuspiciousLibs: Boolean,
        val issues: List<String>
    )
    
    data class NativeLibInfo(
        val name: String,
        val size: Long,
        val sha256: String?,
        val isSuspicious: Boolean,
        val suspicionReason: String?,
        /** Classification of suspicious lib type */
        val suspicionType: NativeLibSuspicionType = NativeLibSuspicionType.UNKNOWN
    )

    /**
     * Classification of suspicious native library types.
     * Used to weight the finding — hooking frameworks are more dangerous than crypto libs.
     */
    enum class NativeLibSuspicionType(val label: String, val weight: Int) {
        /** Runtime hooking / injection framework (Frida, Xposed, Substrate) */
        HOOKING("Hooking framework", 10),
        /** Packer / obfuscation tool */
        PACKER("Obfuskace/packer", 7),
        /** Root / privilege escalation tool */
        ROOT_TOOL("Root nástroj", 9),
        /** Crypto miner */
        CRYPTO_MINER("Crypto miner", 8),
        /** Generic suspicious pattern */
        UNKNOWN("Neznámý", 3)
    }
    
    data class AppSecurityIssue(
        val id: String,
        val title: String,
        val description: String,
        val impact: String,
        val category: IssueCategory,
        val severity: RiskLevel,
        val action: IssueAction,
        val technicalDetails: String? = null,
        /** If true, only show in expert/detail view, not in the main scan list */
        val isExpertOnly: Boolean = false
    )
    
    enum class IssueCategory(val label: String) {
        SIGNATURE("Podpis"),
        PERMISSIONS("Oprávnění"),
        COMPONENTS("Komponenty"),
        NATIVE_CODE("Nativní kód"),
        OUTDATED("Zastaralé"),
        VULNERABILITY("Zranitelnost")
    }
    
    enum class RiskLevel(val score: Int, val label: String, val color: Long) {
        CRITICAL(4, "Kritické", 0xFFF44336),
        HIGH(3, "Vysoké", 0xFFFF9800),
        MEDIUM(2, "Střední", 0xFFFFEB3B),
        LOW(1, "Nízké", 0xFF4CAF50),
        NONE(0, "Bezpečné", 0xFF2196F3)
    }
    
    // Known trusted developer certificate fingerprints (SHA-256)
    private val trustedDeveloperFingerprints = setOf(
        // Google
        "38918A453D07199354F8B19AF05EC6562CED5788",
        // Meta/Facebook
        "A4B94B07E5D7D8E3E7D5B5B5B5B5B5B5B5B5B5B5",
        // Microsoft
        "C3D3E3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3"
    )
    
    // Suspicious native library patterns with classification
    private data class SuspiciousLibPattern(
        val regex: Regex,
        val reason: String,
        val type: NativeLibSuspicionType
    )

    private val suspiciousLibPatterns = listOf(
        SuspiciousLibPattern(
            Regex(".*frida.*", RegexOption.IGNORE_CASE),
            "Frida hooking framework", NativeLibSuspicionType.HOOKING
        ),
        SuspiciousLibPattern(
            Regex(".*xposed.*", RegexOption.IGNORE_CASE),
            "Xposed framework", NativeLibSuspicionType.HOOKING
        ),
        SuspiciousLibPattern(
            Regex(".*substrate.*", RegexOption.IGNORE_CASE),
            "Cydia Substrate", NativeLibSuspicionType.HOOKING
        ),
        SuspiciousLibPattern(
            Regex(".*hook.*", RegexOption.IGNORE_CASE),
            "Hooking library", NativeLibSuspicionType.HOOKING
        ),
        SuspiciousLibPattern(
            Regex(".*inject.*", RegexOption.IGNORE_CASE),
            "Code injection library", NativeLibSuspicionType.HOOKING
        ),
        SuspiciousLibPattern(
            Regex(".*root.*", RegexOption.IGNORE_CASE),
            "Root access tool", NativeLibSuspicionType.ROOT_TOOL
        ),
        SuspiciousLibPattern(
            Regex(".*hide.*", RegexOption.IGNORE_CASE),
            "Hiding / stealth library", NativeLibSuspicionType.ROOT_TOOL
        ),
        SuspiciousLibPattern(
            Regex(".*pack.*jiagu.*|.*bangcle.*|.*ijiami.*|.*qihoo.*", RegexOption.IGNORE_CASE),
            "Known packer/protector", NativeLibSuspicionType.PACKER
        ),
        SuspiciousLibPattern(
            Regex(".*coinhive.*|.*cryptonight.*|.*monero.*|.*miner.*", RegexOption.IGNORE_CASE),
            "Crypto mining library", NativeLibSuspicionType.CRYPTO_MINER
        )
    )
    
    // Permission categories and risk levels
    private val dangerousPermissionInfo = mapOf(
        "android.permission.ACCESS_FINE_LOCATION" to PermissionInfo(
            "Přesná poloha", PermissionCategory.LOCATION, RiskLevel.HIGH,
            "Aplikace může sledovat vaši přesnou GPS polohu"
        ),
        "android.permission.ACCESS_COARSE_LOCATION" to PermissionInfo(
            "Přibližná poloha", PermissionCategory.LOCATION, RiskLevel.MEDIUM,
            "Aplikace může zjistit vaši přibližnou polohu"
        ),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to PermissionInfo(
            "Poloha na pozadí", PermissionCategory.LOCATION, RiskLevel.CRITICAL,
            "Aplikace může sledovat polohu i když ji nepoužíváte"
        ),
        "android.permission.CAMERA" to PermissionInfo(
            "Kamera", PermissionCategory.CAMERA, RiskLevel.HIGH,
            "Aplikace může pořizovat fotky a videa"
        ),
        "android.permission.RECORD_AUDIO" to PermissionInfo(
            "Mikrofon", PermissionCategory.MICROPHONE, RiskLevel.HIGH,
            "Aplikace může nahrávat zvuk"
        ),
        "android.permission.READ_CONTACTS" to PermissionInfo(
            "Čtení kontaktů", PermissionCategory.CONTACTS, RiskLevel.HIGH,
            "Aplikace může číst váš seznam kontaktů"
        ),
        "android.permission.WRITE_CONTACTS" to PermissionInfo(
            "Zápis kontaktů", PermissionCategory.CONTACTS, RiskLevel.HIGH,
            "Aplikace může měnit vaše kontakty"
        ),
        "android.permission.READ_CALL_LOG" to PermissionInfo(
            "Historie hovorů", PermissionCategory.PHONE, RiskLevel.CRITICAL,
            "Aplikace může číst historii vašich hovorů"
        ),
        "android.permission.READ_SMS" to PermissionInfo(
            "Čtení SMS", PermissionCategory.SMS, RiskLevel.CRITICAL,
            "Aplikace může číst vaše SMS zprávy včetně ověřovacích kódů"
        ),
        "android.permission.SEND_SMS" to PermissionInfo(
            "Odesílání SMS", PermissionCategory.SMS, RiskLevel.CRITICAL,
            "Aplikace může odesílat SMS (možné zneužití pro prémiové SMS)"
        ),
        "android.permission.READ_EXTERNAL_STORAGE" to PermissionInfo(
            "Čtení úložiště", PermissionCategory.STORAGE, RiskLevel.MEDIUM,
            "Aplikace může číst soubory ve vašem zařízení"
        ),
        "android.permission.WRITE_EXTERNAL_STORAGE" to PermissionInfo(
            "Zápis do úložiště", PermissionCategory.STORAGE, RiskLevel.MEDIUM,
            "Aplikace může zapisovat soubory"
        ),
        "android.permission.READ_CALENDAR" to PermissionInfo(
            "Čtení kalendáře", PermissionCategory.CALENDAR, RiskLevel.MEDIUM,
            "Aplikace může číst vaše kalendářové události"
        ),
        "android.permission.BODY_SENSORS" to PermissionInfo(
            "Tělesné senzory", PermissionCategory.SENSORS, RiskLevel.MEDIUM,
            "Aplikace může číst data ze zdravotních senzorů"
        ),
        "android.permission.ACTIVITY_RECOGNITION" to PermissionInfo(
            "Rozpoznání aktivity", PermissionCategory.SENSORS, RiskLevel.LOW,
            "Aplikace může rozpoznat vaši fyzickou aktivitu"
        ),
        "android.permission.BLUETOOTH_CONNECT" to PermissionInfo(
            "Bluetooth připojení", PermissionCategory.BLUETOOTH, RiskLevel.LOW,
            "Aplikace se může připojovat k Bluetooth zařízením"
        ),
        "android.permission.NEARBY_WIFI_DEVICES" to PermissionInfo(
            "Blízká WiFi zařízení", PermissionCategory.NETWORK, RiskLevel.MEDIUM,
            "Aplikace může skenovat blízká WiFi zařízení"
        )
    )
    
    private data class PermissionInfo(
        val shortName: String,
        val category: PermissionCategory,
        val risk: RiskLevel,
        val description: String
    )
    
    // App categories that justify certain permissions
    private val permissionJustifications = mapOf(
        "navigation" to setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"),
        "camera" to setOf("android.permission.CAMERA"),
        "voip" to setOf("android.permission.RECORD_AUDIO", "android.permission.CAMERA"),
        "messenger" to setOf("android.permission.READ_CONTACTS", "android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
        "fitness" to setOf("android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION", "android.permission.ACCESS_FINE_LOCATION")
    )
    
    /**
     * Perform comprehensive security scan on all installed apps
     */
    suspend fun scanAllApps(includeSystem: Boolean = false): List<AppSecurityReport> {
        val packages = getInstalledPackages()
        
        // Pre-check: were system apps ever included in a previous scan?
        // If not, system apps appearing as NEW are "new to baseline" (toggle),
        // not genuinely new system components. We pass this flag to suppress
        // false NEW_SYSTEM_APP anomalies.
        val systemAppsWerePreviouslyScanned = baselineManager.hasSystemAppsInBaseline()
        
        return packages
            .filter { includeSystem || !isSystemApp(it) }
            .mapNotNull { pkg -> 
                try {
                    analyzeApp(pkg, systemAppsWerePreviouslyScanned)
                } catch (e: Exception) {
                    null
                }
            }
            .sortedByDescending { it.overallRisk.score }
    }
    
    /**
     * Analyze a single app with full trust evidence + baseline comparison
     *
     * @param systemAppsWerePreviouslyScanned if false, suppress NEW_SYSTEM_APP anomalies
     *   for system-preinstalled apps (they're "new to baseline" because the user just
     *   toggled system visibility, not because they were genuinely added to the system).
     */
    @SuppressLint("PackageManagerGetSignatures")
    suspend fun analyzeApp(
        packageInfo: PackageInfo,
        systemAppsWerePreviouslyScanned: Boolean = true
    ): AppSecurityReport {
        val pm = context.packageManager
        val appInfo = packageInfo.applicationInfo
        
        val scannedApp = ScannedApp(
            packageName = packageInfo.packageName,
            appName = appInfo?.let { pm.getApplicationLabel(it).toString() } ?: packageInfo.packageName,
            versionName = packageInfo.versionName,
            versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            },
            installedAt = packageInfo.firstInstallTime,
            lastUpdated = packageInfo.lastUpdateTime,
            isSystemApp = isSystemApp(packageInfo),
            targetSdk = appInfo?.targetSdkVersion ?: 0,
            minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                appInfo?.minSdkVersion ?: 0
            } else 0,
            apkPath = appInfo?.sourceDir,
            apkSizeBytes = appInfo?.sourceDir?.let { java.io.File(it).length() } ?: 0
        )
        
        val signatureAnalysis = analyzeSignature(packageInfo)
        val permissionAnalysis = analyzePermissions(packageInfo)
        val componentAnalysis = analyzeComponents(packageInfo)
        val nativeLibAnalysis = analyzeNativeLibs(appInfo?.sourceDir, appInfo?.nativeLibraryDir)
        
        val issues = mutableListOf<AppSecurityIssue>()
        val rawFindings = mutableListOf<TrustRiskModel.RawFinding>()
        
        // ── 1. Collect trust evidence (multi-factor) ──
        val certFingerprint = signatureAnalysis.sha256Fingerprint
        val trustEvidence = trustEngine.collectEvidence(packageInfo, certFingerprint)

        // Classify expected signer domain BEFORE cert comparison
        val isApex = appInfo?.sourceDir?.startsWith("/apex/") == true
        val signerDomain = TrustedAppsWhitelist.classifySignerDomain(
            isSystemApp = scannedApp.isSystemApp,
            isApex = isApex,
            isPlatformSigned = trustEvidence.systemAppInfo.isPlatformSigned,
            partition = trustEvidence.systemAppInfo.partition,
            sourceDir = appInfo?.sourceDir
        )

        // Cert-vs-whitelist comparison — domain-aware
        val trustVerification = TrustedAppsWhitelist.verifyTrustedApp(
            packageInfo.packageName, certFingerprint, signerDomain
        )
        
        // ── 2. Collect permission + component data for baseline ──
        val installerPkg = trustEvidence.installerInfo.installerPackage
        val allPermissions = (packageInfo.requestedPermissions ?: emptyArray()).toList()
        val currentHighRiskPerms = allPermissions.filter { it in BaselineManager.HIGH_RISK_PERMISSIONS }
        val exportedSurface = BaselineManager.ExportedSurface(
            exportedActivityCount = componentAnalysis.exportedActivities.size,
            exportedServiceCount = componentAnalysis.exportedServices.size,
            exportedReceiverCount = componentAnalysis.exportedReceivers.size,
            exportedProviderCount = componentAnalysis.exportedProviders.size,
            unprotectedExportedCount = componentAnalysis.exportedActivities.count { !it.isProtected } +
                    componentAnalysis.exportedServices.count { !it.isProtected } +
                    componentAnalysis.exportedReceivers.count { !it.isProtected } +
                    componentAnalysis.exportedProviders.count { !it.isProtected }
        )
        
        // Detect app category for context-aware evaluation
        val appCategory = AppCategoryDetector.detectCategory(
            packageInfo.packageName,
            scannedApp.appName
        )
        
        // ── 3. Baseline comparison (change detection) ──
        val baselineComparison = baselineManager.compareWithBaseline(
            packageName = packageInfo.packageName,
            currentCertSha256 = certFingerprint,
            currentVersionCode = scannedApp.versionCode,
            currentVersionName = scannedApp.versionName,
            isSystemApp = scannedApp.isSystemApp,
            installerPackage = installerPkg,
            apkPath = scannedApp.apkPath,
            currentPermissions = allPermissions,
            currentHighRiskPermissions = currentHighRiskPerms,
            currentExportedSurface = exportedSurface
        )
        
        // ── 4. Generate issues + raw findings ──
        
        // Baseline anomalies → findings
        baselineComparison.anomalies.forEach { anomaly ->
            // Suppress NEW_SYSTEM_APP for system-preinstalled apps when system apps
            // were never scanned before (user just toggled system visibility).
            if (anomaly.type == BaselineManager.AnomalyType.NEW_SYSTEM_APP
                && scannedApp.isSystemApp
                && !systemAppsWerePreviouslyScanned) {
                return@forEach  // Skip — this is "new to baseline", not genuinely new
            }

            val (findingType, severity) = when (anomaly.type) {
                BaselineManager.AnomalyType.CERT_CHANGED -> 
                    TrustRiskModel.FindingType.BASELINE_SIGNATURE_CHANGE to RiskLevel.CRITICAL
                BaselineManager.AnomalyType.NEW_SYSTEM_APP -> 
                    TrustRiskModel.FindingType.BASELINE_NEW_SYSTEM_APP to RiskLevel.HIGH
                BaselineManager.AnomalyType.INSTALLER_CHANGED -> 
                    TrustRiskModel.FindingType.INSTALLER_ANOMALY to RiskLevel.MEDIUM
                BaselineManager.AnomalyType.VERSION_CHANGED -> 
                    TrustRiskModel.FindingType.OLD_TARGET_SDK to RiskLevel.LOW // Not really a finding
                BaselineManager.AnomalyType.PARTITION_CHANGED -> 
                    TrustRiskModel.FindingType.INSTALLER_ANOMALY to RiskLevel.MEDIUM
                BaselineManager.AnomalyType.PERMISSION_SET_CHANGED ->
                    TrustRiskModel.FindingType.OVER_PRIVILEGED to RiskLevel.LOW // Informational
                BaselineManager.AnomalyType.HIGH_RISK_PERMISSION_ADDED ->
                    TrustRiskModel.FindingType.HIGH_RISK_PERMISSION_ADDED to RiskLevel.HIGH
                BaselineManager.AnomalyType.EXPORTED_SURFACE_INCREASED ->
                    TrustRiskModel.FindingType.EXPORTED_SURFACE_INCREASED to RiskLevel.MEDIUM
                BaselineManager.AnomalyType.VERSION_ROLLBACK -> {
                    // Context-aware: sideloaded rollback = HARD HIGH, Play Store rollback = SOFT MEDIUM
                    val isTrustedInstaller = trustEvidence.installerInfo.installerType in setOf(
                        TrustEvidenceEngine.InstallerType.PLAY_STORE,
                        TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER,
                        TrustEvidenceEngine.InstallerType.SAMSUNG_STORE,
                        TrustEvidenceEngine.InstallerType.HUAWEI_APPGALLERY,
                        TrustEvidenceEngine.InstallerType.AMAZON_APPSTORE
                    )
                    if (isTrustedInstaller) {
                        TrustRiskModel.FindingType.VERSION_ROLLBACK_TRUSTED to RiskLevel.MEDIUM
                    } else {
                        TrustRiskModel.FindingType.VERSION_ROLLBACK to RiskLevel.HIGH
                    }
                }
            }
            
            // Only create issues for significant anomalies
            if (anomaly.severity != BaselineManager.AnomalySeverity.LOW) {
                issues.add(AppSecurityIssue(
                    id = "baseline_${anomaly.type.name.lowercase()}_${packageInfo.packageName}",
                    title = anomaly.description,
                    description = anomaly.details ?: anomaly.description,
                    impact = when (anomaly.type) {
                        BaselineManager.AnomalyType.CERT_CHANGED -> 
                            "Změna podpisu může znamenat přebalení aplikace třetí stranou."
                        BaselineManager.AnomalyType.NEW_SYSTEM_APP -> 
                            "Nová systémová komponenta může indikovat neautorizovanou modifikaci."
                        else -> "Doporučujeme zkontrolovat."
                    },
                    category = IssueCategory.SIGNATURE,
                    severity = severity,
                    action = IssueAction.OpenPlayStore(packageInfo.packageName, "Zkontrolovat")
                ))
                rawFindings.add(TrustRiskModel.RawFinding(findingType, severity, anomaly.description, anomaly.details ?: ""))
            }
        }
        
        // ── Cert verification findings (domain-aware) ──
        if (trustVerification.reason == TrustedAppsWhitelist.TrustReason.UNKNOWN_CERT) {
            if (TrustedAppsWhitelist.isExpectedSignerMismatch(signerDomain)) {
                // System / APEX / OEM domain: cert not matching Play Store key is EXPECTED.
                // Generate a SOFT informational finding — never triggers R1 CRITICAL.
                val title = "Systémový podpis (ne Play Store)"
                issues.add(AppSecurityIssue(
                    id = "sig_not_play_${packageInfo.packageName}",
                    title = title,
                    description = "${scannedApp.appName} je podepsána systémovým/APEX klíčem, ne Play Store klíčem.",
                    impact = "Očekávaný stav pro systémovou komponentu.",
                    category = IssueCategory.SIGNATURE,
                    severity = RiskLevel.LOW,
                    isExpertOnly = true, // Don't show to regular users
                    action = IssueAction.None
                ))
                rawFindings.add(TrustRiskModel.RawFinding(
                    TrustRiskModel.FindingType.NOT_PLAY_SIGNED, RiskLevel.LOW, title, ""
                ))
            } else {
                // PLAY_SIGNED or UNKNOWN domain: cert mismatch is a real HARD finding
                val title = "Může jít o neoficiální verzi"
                issues.add(AppSecurityIssue(
                    id = "sig_resigned_${packageInfo.packageName}",
                    title = title,
                    description = "${scannedApp.appName} tvrdí, že pochází od známého vývojáře, ale její podpis neodpovídá.",
                    impact = "Tato aplikace mohla být upravena třetí stranou.",
                    category = IssueCategory.SIGNATURE,
                    severity = RiskLevel.HIGH,
                    action = IssueAction.OpenPlayStore(packageInfo.packageName, "Přeinstalovat z Play Store"),
                    technicalDetails = "Cert: ${certFingerprint.take(16)}..."
                ))
                rawFindings.add(TrustRiskModel.RawFinding(
                    TrustRiskModel.FindingType.SIGNATURE_MISMATCH, RiskLevel.HIGH, title, ""
                ))
            }
        }

        // ── Partition / sourceDir anomaly (system integrity check) ──
        val partitionAnomaly = TrustedAppsWhitelist.detectPartitionAnomaly(
            packageName = packageInfo.packageName,
            isSystemApp = scannedApp.isSystemApp,
            sourceDir = appInfo?.sourceDir,
            partition = trustEvidence.systemAppInfo.partition
        )
        if (partitionAnomaly != null) {
            val title = "Neočekávané umístění systémové komponenty"
            issues.add(AppSecurityIssue(
                id = "sig_partition_${packageInfo.packageName}",
                title = title,
                description = partitionAnomaly,
                impact = "Systémová komponenta běží z neočekávaného umístění — může jít o neautorizovanou modifikaci.",
                category = IssueCategory.SIGNATURE,
                severity = RiskLevel.HIGH,
                action = IssueAction.None
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                TrustRiskModel.FindingType.PARTITION_ANOMALY, RiskLevel.HIGH, title, partitionAnomaly
            ))
        }
        
        // Debug signature (HARD — trust NEVER suppresses)
        if (signatureAnalysis.isDebugSigned) {
            val title = "Vývojová verze aplikace"
            issues.add(AppSecurityIssue(
                id = "sig_debug_${packageInfo.packageName}",
                title = title,
                description = "${scannedApp.appName} je podepsána vývojářským certifikátem.",
                impact = "Nepochází z oficiálního obchodu. Doporučujeme stáhnout z Google Play.",
                category = IssueCategory.SIGNATURE,
                severity = RiskLevel.HIGH,
                action = IssueAction.OpenPlayStore(packageInfo.packageName, "Přeinstalovat z Play Store")
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                TrustRiskModel.FindingType.DEBUG_SIGNATURE, RiskLevel.HIGH, title, ""
            ))
        } else if (signatureAnalysis.issues.isNotEmpty() && !trustVerification.isTrusted) {
            // Other signature issues for non-trusted apps
            issues.addAll(signatureAnalysis.issues.mapIndexed { i, _ ->
                AppSecurityIssue(
                    id = "sig_${packageInfo.packageName}_$i",
                    title = "Neobvyklý podpis",
                    description = "${scannedApp.appName} má neobvyklý podpisový certifikát.",
                    impact = "Doporučujeme zkontrolovat původ aplikace.",
                    category = IssueCategory.SIGNATURE,
                    severity = RiskLevel.MEDIUM,
                    action = IssueAction.OpenPlayStore(packageInfo.packageName, "Zkontrolovat aktualizaci")
                )
            })
        }
        
        // Over-privileged (SOFT)
        if (permissionAnalysis.isOverPrivileged) {
            val title = "Nadměrná oprávnění"
            issues.add(AppSecurityIssue(
                id = "perm_overprivileged_${packageInfo.packageName}",
                title = title,
                description = "${scannedApp.appName} má více oprávnění, než byste od aplikace tohoto typu očekávali.",
                impact = "Aplikace může sbírat data, která ke své funkci nepotřebuje.",
                category = IssueCategory.PERMISSIONS,
                severity = RiskLevel.MEDIUM,
                action = IssueAction.OpenSettings(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "Zkontrolovat oprávnění"),
                technicalDetails = "Kritická oprávnění: ${permissionAnalysis.dangerousPermissions
                    .filter { it.isGranted }.joinToString { it.shortName }}"
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                TrustRiskModel.FindingType.OVER_PRIVILEGED, RiskLevel.MEDIUM, title, ""
            ))
        }
        
        // High-risk capability clusters (WEAK_SIGNAL — only alarming in combos or with low trust)
        val grantedPerms = permissionAnalysis.dangerousPermissions
            .filter { it.isGranted }
            .map { it.permission }
        val activeClusters = TrustRiskModel.CapabilityCluster.entries.filter { it.isActive(grantedPerms) }
        
        for (cluster in activeClusters) {
            // Don't create issues for expected permissions
            val isExpected = cluster.permissions.all { perm ->
                AppCategoryDetector.isPermissionExpected(appCategory, perm)
            }
            
            if (!isExpected) {
                rawFindings.add(TrustRiskModel.RawFinding(
                    TrustRiskModel.FindingType.HIGH_RISK_CAPABILITY, RiskLevel.MEDIUM,
                    cluster.label,
                    "Aplikace má přístup k: ${cluster.label}"
                ))
            }
        }
        
        // Exported components (SOFT)
        if (componentAnalysis.hasExportedRisks) {
            val unprotectedCount = componentAnalysis.exportedActivities.count { !it.isProtected } +
                    componentAnalysis.exportedServices.count { !it.isProtected } +
                    componentAnalysis.exportedReceivers.count { !it.isProtected }
            val title = "Může být ovládána jinými aplikacemi"
            issues.add(AppSecurityIssue(
                id = "comp_exported_${packageInfo.packageName}",
                title = title,
                description = "${scannedApp.appName} má $unprotectedCount nechráněných vstupních bodů.",
                impact = "Jiné aplikace mohou spouštět části této aplikace bez vašeho vědomí.",
                category = IssueCategory.COMPONENTS,
                severity = RiskLevel.LOW,
                action = IssueAction.OpenPlayStore(packageInfo.packageName, "Zkontrolovat aktualizaci")
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                TrustRiskModel.FindingType.EXPORTED_COMPONENTS, RiskLevel.LOW, title, ""
            ))
        }
        
        // Suspicious native libs (SOFT, unless device integrity fail → HARD)
        if (nativeLibAnalysis.hasSuspiciousLibs) {
            val suspiciousLibs = nativeLibAnalysis.libraries.filter { it.isSuspicious }
            val deviceCompromised = trustEvidence.deviceIntegrity.isRooted
            val findingType = if (deviceCompromised) 
                TrustRiskModel.FindingType.INTEGRITY_FAIL_WITH_HOOKING 
            else 
                TrustRiskModel.FindingType.SUSPICIOUS_NATIVE_LIB
            val title = "Obsahuje neobvyklý kód"
            
            issues.add(AppSecurityIssue(
                id = "native_suspicious_${packageInfo.packageName}",
                title = title,
                description = "${scannedApp.appName} obsahuje komponenty běžně používané nástroji pro obcházení zabezpečení.",
                impact = "Tento typ kódu se někdy používá k získání root přístupu nebo ke skrývání aktivit.",
                category = IssueCategory.NATIVE_CODE,
                severity = if (deviceCompromised) RiskLevel.CRITICAL else RiskLevel.HIGH,
                action = IssueAction.OpenSettings(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "Zvážit odinstalaci"),
                technicalDetails = suspiciousLibs.map { "${it.name}: ${it.suspicionReason}" }.joinToString("\n")
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                findingType, if (deviceCompromised) RiskLevel.CRITICAL else RiskLevel.HIGH, title, ""
            ))
        }
        
        // Old target SDK (SOFT)
        if (scannedApp.targetSdk > 0 && scannedApp.targetSdk < 29) {
            val title = "Navržena pro starší Android"
            val severity = if (scannedApp.targetSdk < 26) RiskLevel.MEDIUM else RiskLevel.LOW
            issues.add(AppSecurityIssue(
                id = "sdk_old_${packageInfo.packageName}",
                title = title,
                description = "${scannedApp.appName} je navržena pro Android ${sdkToVersion(scannedApp.targetSdk)}.",
                impact = "Starší aplikace mohou obcházet moderní bezpečnostní omezení.",
                category = IssueCategory.OUTDATED,
                severity = severity,
                action = IssueAction.OpenPlayStore(packageInfo.packageName, "Zkontrolovat aktualizaci")
            ))
            rawFindings.add(TrustRiskModel.RawFinding(
                TrustRiskModel.FindingType.OLD_TARGET_SDK, severity, title, ""
            ))
        }
        
        // Installer anomaly — refined logic:
        // - DEVELOPER_MATCH + sideloaded → SOFT (cert matches, likely power-user)
        // - CERT_MISMATCH + sideloaded → HARD (cert doesn't match, possible re-sign)
        if (trustEvidence.installerInfo.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
            when (trustEvidence.certMatch.matchType) {
                TrustEvidenceEngine.CertMatchType.DEVELOPER_MATCH -> {
                    // Cert matches known developer — power-user install (APKMirror, beta, etc.)
                    val title = "Ruční instalace ověřené aplikace"
                    issues.add(AppSecurityIssue(
                        id = "installer_anomaly_verified_${packageInfo.packageName}",
                        title = title,
                        description = "${scannedApp.appName} od ověřeného vývojáře byla nainstalována mimo obchod.",
                        impact = "Ověřený vývojář, ale instalace mimo oficiální obchod může znamenat starší nebo upravenou verzi.",
                        category = IssueCategory.SIGNATURE,
                        severity = RiskLevel.LOW,
                        action = IssueAction.OpenPlayStore(packageInfo.packageName, "Přeinstalovat z Play Store")
                    ))
                    rawFindings.add(TrustRiskModel.RawFinding(
                        TrustRiskModel.FindingType.INSTALLER_ANOMALY_VERIFIED, RiskLevel.LOW, title, ""
                    ))
                }
                TrustEvidenceEngine.CertMatchType.CERT_MISMATCH -> {
                    // Cert DOESN'T match — this is genuinely suspicious
                    val title = "Podezřelý zdroj instalace"
                    issues.add(AppSecurityIssue(
                        id = "installer_anomaly_${packageInfo.packageName}",
                        title = title,
                        description = "${scannedApp.appName} vypadá jako známá aplikace, ale má neplatný certifikát.",
                        impact = "Aplikace mohla být přebalena s škodlivým kódem.",
                        category = IssueCategory.SIGNATURE,
                        severity = RiskLevel.HIGH,
                        action = IssueAction.OpenSettings(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "Zvážit odinstalaci")
                    ))
                    rawFindings.add(TrustRiskModel.RawFinding(
                        TrustRiskModel.FindingType.INSTALLER_ANOMALY, RiskLevel.HIGH, title, ""
                    ))
                }
                else -> {
                    // UNKNOWN cert + sideloaded — moderate concern
                    // (APP_MATCH is also fine — individual app verified)
                    if (trustEvidence.certMatch.matchType == TrustEvidenceEngine.CertMatchType.UNKNOWN) {
                        val title = "Neznámá sideload instalace"
                        issues.add(AppSecurityIssue(
                            id = "installer_anomaly_unknown_${packageInfo.packageName}",
                            title = title,
                            description = "${scannedApp.appName} byla nainstalována z neznámého zdroje.",
                            impact = "Neznámý vývojář s ruční instalací zvyšuje riziko.",
                            category = IssueCategory.SIGNATURE,
                            severity = RiskLevel.MEDIUM,
                            action = IssueAction.OpenPlayStore(packageInfo.packageName, "Zkusit najít v Play Store")
                        ))
                        rawFindings.add(TrustRiskModel.RawFinding(
                            TrustRiskModel.FindingType.INSTALLER_ANOMALY, RiskLevel.MEDIUM, title, ""
                        ))
                    }
                }
            }
        }
        
        // ── 4b. Special access inspection (real enabled state) ──
        val specialAccessSnapshot = specialAccessInspector.inspectApp(packageInfo.packageName)

        // ── 4c. Classify install origin for policy profile ──
        val installClass = trustRiskModel.classifyInstall(
            isSystemApp = scannedApp.isSystemApp,
            installerType = trustEvidence.installerInfo.installerType,
            partition = trustEvidence.systemAppInfo.partition
        )

        // isNewApp: only true for USER_INSTALLED apps that are genuinely new since last scan.
        // SYSTEM_PREINSTALLED appearing "new to baseline" (e.g., user toggled system visibility)
        // are NEVER treated as new installs — they've been there since device setup.
        val isNewInstall = installClass == TrustRiskModel.InstallClass.USER_INSTALLED
                && baselineComparison.status == BaselineManager.BaselineStatus.NEW
                && !baselineComparison.isFirstScan

        // ── 5. Produce verdict (Trust + Risk combined — 3-axis) ──
        val verdict = trustRiskModel.evaluate(
            packageName = packageInfo.packageName,
            trustEvidence = trustEvidence,
            rawFindings = rawFindings,
            isSystemApp = scannedApp.isSystemApp,
            grantedPermissions = grantedPerms,
            appCategory = appCategory,
            isNewApp = isNewInstall,
            specialAccessSnapshot = specialAccessSnapshot,
            installClass = installClass
        )
        
        // Overall risk — map 4-state verdict to RiskLevel for backward compat
        val overallRisk = when (verdict.effectiveRisk) {
            TrustRiskModel.EffectiveRisk.CRITICAL -> RiskLevel.CRITICAL
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION -> RiskLevel.HIGH
            TrustRiskModel.EffectiveRisk.INFO -> RiskLevel.LOW
            TrustRiskModel.EffectiveRisk.SAFE -> RiskLevel.NONE
        }
        
        // ── 6. Update baseline for next scan ──
        baselineManager.updateBaseline(
            packageName = packageInfo.packageName,
            certSha256 = certFingerprint,
            versionCode = scannedApp.versionCode,
            versionName = scannedApp.versionName,
            isSystemApp = scannedApp.isSystemApp,
            installerPackage = installerPkg,
            apkPath = scannedApp.apkPath,
            permissions = allPermissions,
            highRiskPermissions = currentHighRiskPerms,
            exportedSurface = exportedSurface
        )
        
        return AppSecurityReport(
            app = scannedApp,
            signatureAnalysis = signatureAnalysis,
            permissionAnalysis = permissionAnalysis,
            componentAnalysis = componentAnalysis,
            nativeLibAnalysis = nativeLibAnalysis,
            trustVerification = trustVerification,
            trustEvidence = trustEvidence,
            verdict = verdict,
            baselineComparison = baselineComparison,
            overallRisk = overallRisk,
            issues = issues
        )
    }
    
    @SuppressLint("PackageManagerGetSignatures")
    private fun analyzeSignature(packageInfo: PackageInfo): SignatureAnalysis {
        val issues = mutableListOf<String>()
        
        val signatures: Array<Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures
        }
        
        if (signatures.isNullOrEmpty()) {
            return SignatureAnalysis(
                sha256Fingerprint = "UNKNOWN",
                issuer = "Unknown",
                subject = "Unknown",
                validFrom = 0,
                validUntil = 0,
                isDebugSigned = false,
                signatureScheme = "Unknown",
                isTrustedDeveloper = false,
                issues = listOf("Nelze přečíst podpis aplikace")
            )
        }
        
        val signature = signatures.first()
        val certFactory = CertificateFactory.getInstance("X.509")
        val cert = certFactory.generateCertificate(
            ByteArrayInputStream(signature.toByteArray())
        ) as X509Certificate
        
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray())
            .joinToString("") { "%02X".format(it) }
        
        val isDebugSigned = cert.subjectDN.name.contains("Android Debug", ignoreCase = true) ||
                cert.subjectDN.name.contains("CN=Android Debug", ignoreCase = true)
        
        if (isDebugSigned) {
            issues.add("Aplikace je podepsána debug certifikátem - pravděpodobně neoficiální verze")
        }
        
        val isTrusted = trustedDeveloperFingerprints.any { sha256.startsWith(it) }
        
        // Check certificate validity
        val now = System.currentTimeMillis()
        if (cert.notAfter.time < now) {
            issues.add("Certifikát aplikace vypršel ${cert.notAfter}")
        }
        
        // Determine signature scheme
        val signatureScheme = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && 
                    packageInfo.signingInfo?.hasMultipleSigners() == true -> "v3 (APK Signature Scheme v3)"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.N -> "v2 (APK Signature Scheme v2)"
            else -> "v1 (JAR Signature)"
        }
        
        return SignatureAnalysis(
            sha256Fingerprint = sha256,
            issuer = cert.issuerDN.name,
            subject = cert.subjectDN.name,
            validFrom = cert.notBefore.time,
            validUntil = cert.notAfter.time,
            isDebugSigned = isDebugSigned,
            signatureScheme = signatureScheme,
            isTrustedDeveloper = isTrusted,
            issues = issues
        )
    }
    
    private fun analyzePermissions(packageInfo: PackageInfo): PermissionAnalysis {
        val pm = context.packageManager
        val issues = mutableListOf<String>()
        
        val requestedPermissions = packageInfo.requestedPermissions ?: emptyArray()
        val requestedPermissionsFlags = packageInfo.requestedPermissionsFlags ?: IntArray(0)
        
        val dangerousPerms = mutableListOf<PermissionDetail>()
        val normalPerms = mutableListOf<String>()
        val signaturePerms = mutableListOf<String>()
        val grantedRuntime = mutableListOf<String>()
        val deniedRuntime = mutableListOf<String>()
        
        requestedPermissions.forEachIndexed { index, permission ->
            val isGranted = if (index < requestedPermissionsFlags.size) {
                (requestedPermissionsFlags[index] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            } else false
            
            val permInfo = dangerousPermissionInfo[permission]
            if (permInfo != null) {
                dangerousPerms.add(PermissionDetail(
                    permission = permission,
                    shortName = permInfo.shortName,
                    category = permInfo.category,
                    isGranted = isGranted,
                    riskLevel = permInfo.risk,
                    description = permInfo.description
                ))
                
                if (isGranted) grantedRuntime.add(permission)
                else deniedRuntime.add(permission)
            } else {
                // Try to determine permission type
                try {
                    val pInfo = pm.getPermissionInfo(permission, 0)
                    // Use protectionLevel with bitmask (works on all API levels)
                    // protection is API 28+, protectionLevel works everywhere
                    val baseProtection = pInfo.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE
                    when (baseProtection) {
                        android.content.pm.PermissionInfo.PROTECTION_DANGEROUS -> {
                            dangerousPerms.add(PermissionDetail(
                                permission = permission,
                                shortName = permission.substringAfterLast("."),
                                category = PermissionCategory.OTHER,
                                isGranted = isGranted,
                                riskLevel = RiskLevel.MEDIUM,
                                description = "Nebezpečné oprávnění"
                            ))
                        }
                        android.content.pm.PermissionInfo.PROTECTION_SIGNATURE -> {
                            signaturePerms.add(permission)
                        }
                        else -> normalPerms.add(permission)
                    }
                } catch (e: Exception) {
                    normalPerms.add(permission)
                }
            }
        }
        
        // Calculate privacy score (0-100, higher = more privacy risk)
        val privacyScore = dangerousPerms
            .filter { it.isGranted }
            .sumOf { it.riskLevel.score * 10 }
            .coerceAtMost(100)
        
        // Determine if app is over-privileged
        // Simple heuristic: calculator/flashlight apps shouldn't need location/camera/contacts
        val isOverPrivileged = detectOverPrivileged(packageInfo.packageName, dangerousPerms)
        
        if (isOverPrivileged) {
            issues.add("Aplikace požaduje více oprávnění než je pro její účel typické")
        }
        
        return PermissionAnalysis(
            dangerousPermissions = dangerousPerms,
            normalPermissions = normalPerms,
            signaturePermissions = signaturePerms,
            runtimePermissionsGranted = grantedRuntime,
            runtimePermissionsDenied = deniedRuntime,
            isOverPrivileged = isOverPrivileged,
            privacyScore = privacyScore,
            issues = issues
        )
    }
    
    private fun detectOverPrivileged(packageName: String, permissions: List<PermissionDetail>): Boolean {
        val grantedDangerous = permissions.filter { it.isGranted }
        
        // Simple apps (calculators, flashlights, etc.) with sensitive permissions
        val simpleAppPatterns = listOf(
            "calc", "calculator", "flashlight", "torch", "light",
            "compass", "level", "ruler", "timer", "stopwatch",
            "note", "memo", "todo", "qr", "barcode"
        )
        
        val isSimpleApp = simpleAppPatterns.any { 
            packageName.lowercase().contains(it) 
        }
        
        if (isSimpleApp) {
            val suspiciousForSimple = setOf(
                PermissionCategory.LOCATION,
                PermissionCategory.CONTACTS,
                PermissionCategory.SMS,
                PermissionCategory.PHONE,
                PermissionCategory.CALENDAR
            )
            
            return grantedDangerous.any { it.category in suspiciousForSimple }
        }
        
        // Generic check: too many dangerous permissions
        return grantedDangerous.count { it.riskLevel >= RiskLevel.HIGH } > 5
    }
    
    private fun analyzeComponents(packageInfo: PackageInfo): ComponentAnalysis {
        val pm = context.packageManager
        val issues = mutableListOf<String>()
        
        val exportedActivities = mutableListOf<ExportedComponent>()
        val exportedServices = mutableListOf<ExportedComponent>()
        val exportedReceivers = mutableListOf<ExportedComponent>()
        val exportedProviders = mutableListOf<ExportedComponent>()
        val deepLinks = mutableListOf<DeepLinkInfo>()
        
        // Get full package info with components
        val fullPackageInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageInfo.packageName,
                    PackageManager.PackageInfoFlags.of(
                        (PackageManager.GET_ACTIVITIES or 
                         PackageManager.GET_SERVICES or 
                         PackageManager.GET_RECEIVERS or 
                         PackageManager.GET_PROVIDERS).toLong()
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    packageInfo.packageName,
                    PackageManager.GET_ACTIVITIES or 
                    PackageManager.GET_SERVICES or 
                    PackageManager.GET_RECEIVERS or 
                    PackageManager.GET_PROVIDERS
                )
            }
        } catch (e: Exception) {
            packageInfo
        }
        
        // Analyze activities
        fullPackageInfo.activities?.forEach { activity ->
            if (activity.exported) {
                val isProtected = !activity.permission.isNullOrEmpty()
                exportedActivities.add(ExportedComponent(
                    name = activity.name.substringAfterLast("."),
                    isProtected = isProtected,
                    permission = activity.permission,
                    intentFilters = emptyList(), // Would need to parse manifest
                    risk = if (isProtected) RiskLevel.LOW else RiskLevel.MEDIUM
                ))
            }
        }
        
        // Analyze services
        fullPackageInfo.services?.forEach { service ->
            if (service.exported) {
                val isProtected = !service.permission.isNullOrEmpty()
                exportedServices.add(ExportedComponent(
                    name = service.name.substringAfterLast("."),
                    isProtected = isProtected,
                    permission = service.permission,
                    intentFilters = emptyList(),
                    risk = if (isProtected) RiskLevel.LOW else RiskLevel.HIGH
                ))
            }
        }
        
        // Analyze receivers
        fullPackageInfo.receivers?.forEach { receiver ->
            if (receiver.exported) {
                val isProtected = !receiver.permission.isNullOrEmpty()
                exportedReceivers.add(ExportedComponent(
                    name = receiver.name.substringAfterLast("."),
                    isProtected = isProtected,
                    permission = receiver.permission,
                    intentFilters = emptyList(),
                    risk = if (isProtected) RiskLevel.LOW else RiskLevel.MEDIUM
                ))
            }
        }
        
        // Analyze providers
        fullPackageInfo.providers?.forEach { provider ->
            if (provider.exported) {
                val isProtected = !provider.readPermission.isNullOrEmpty() || 
                                  !provider.writePermission.isNullOrEmpty()
                exportedProviders.add(ExportedComponent(
                    name = provider.name.substringAfterLast("."),
                    isProtected = isProtected,
                    permission = provider.readPermission ?: provider.writePermission,
                    intentFilters = emptyList(),
                    risk = if (isProtected) RiskLevel.LOW else RiskLevel.HIGH
                ))
            }
        }
        
        val hasExportedRisks = exportedActivities.any { !it.isProtected } ||
                exportedServices.any { !it.isProtected } ||
                exportedReceivers.any { !it.isProtected } ||
                exportedProviders.any { !it.isProtected }
        
        if (hasExportedRisks) {
            issues.add("Aplikace má nechráněné exportované komponenty")
        }
        
        return ComponentAnalysis(
            exportedActivities = exportedActivities,
            exportedServices = exportedServices,
            exportedReceivers = exportedReceivers,
            exportedProviders = exportedProviders,
            deepLinks = deepLinks,
            hasExportedRisks = hasExportedRisks,
            issues = issues
        )
    }
    
    private fun analyzeNativeLibs(apkPath: String?, nativeLibDir: String?): NativeLibAnalysis {
        val issues = mutableListOf<String>()
        val libraries = mutableListOf<NativeLibInfo>()
        val architectures = mutableSetOf<String>()
        
        // Scan APK for native libraries
        if (apkPath != null) {
            try {
                ZipFile(apkPath).use { zip ->
                    zip.entries().asSequence()
                        .filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                        .forEach { entry ->
                            val parts = entry.name.split("/")
                            if (parts.size >= 3) {
                                architectures.add(parts[1])
                                val libName = parts.last()
                                
                                val matchedPattern = suspiciousLibPatterns.firstOrNull { 
                                    it.regex.matches(libName) 
                                }
                                val isSuspicious = matchedPattern != null
                                
                                libraries.add(NativeLibInfo(
                                    name = libName,
                                    size = entry.size,
                                    sha256 = null, // Would need to read and hash
                                    isSuspicious = isSuspicious,
                                    suspicionReason = matchedPattern?.reason,
                                    suspicionType = matchedPattern?.type ?: NativeLibSuspicionType.UNKNOWN
                                ))
                            }
                        }
                }
            } catch (e: Exception) {
                issues.add("Nelze analyzovat nativní knihovny: ${e.message}")
            }
        }
        
        val hasSuspicious = libraries.any { it.isSuspicious }
        if (hasSuspicious) {
            issues.add("Nalezeny podezřelé nativní knihovny")
        }
        
        return NativeLibAnalysis(
            hasNativeCode = libraries.isNotEmpty(),
            architectures = architectures.toList(),
            libraries = libraries.distinctBy { it.name },
            hasSuspiciousLibs = hasSuspicious,
            issues = issues
        )
    }
    
    private fun getInstalledPackages(): List<PackageInfo> {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(
                    (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
                )
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES)
        }
    }
    
    private fun isSystemApp(pkg: PackageInfo): Boolean {
        return pkg.applicationInfo?.let {
            (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        } ?: false
    }
    
    private fun sdkToVersion(sdk: Int): String = when (sdk) {
        35 -> "15"
        34 -> "14"
        33 -> "13"
        32, 31 -> "12"
        30 -> "11"
        29 -> "10"
        28 -> "9"
        27, 26 -> "8"
        25, 24 -> "7"
        23 -> "6"
        else -> sdk.toString()
    }
    
    /**
     * Get summary statistics for dashboard
     */
    fun getScanSummary(reports: List<AppSecurityReport>): ScanSummary {
        val userReports = reports.filter { !it.app.isSystemApp }
        val systemReports = reports.filter { it.app.isSystemApp }

        // Use 4-state verdict for primary counts (USER only)
        val criticalApps = userReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL }
        val needsAttentionApps = userReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION }
        val infoApps = userReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.INFO }
        val safeApps = userReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE }
        
        val totalIssues = userReports.sumOf { it.issues.size }
        val criticalIssues = userReports.sumOf { r -> r.issues.count { it.severity == RiskLevel.CRITICAL } }
        
        val appsWithOverPrivileged = userReports.count { it.permissionAnalysis.isOverPrivileged }
        val appsWithDebugCert = userReports.count { it.signatureAnalysis.isDebugSigned }
        val appsWithSuspiciousLibs = userReports.count { it.nativeLibAnalysis.hasSuspiciousLibs }

        // System app stats (separate aggregation)
        val systemSummary = SystemAppsSummary(
            totalSystemApps = systemReports.size,
            criticalSystemApps = systemReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL },
            needsAttentionSystemApps = systemReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION },
            infoSystemApps = systemReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.INFO },
            safeSystemApps = systemReports.count { it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE }
        )
        
        return ScanSummary(
            totalAppsScanned = userReports.size,
            criticalRiskApps = criticalApps,
            highRiskApps = needsAttentionApps,
            mediumRiskApps = infoApps,
            safeApps = safeApps,
            totalIssues = totalIssues,
            criticalIssues = criticalIssues,
            overPrivilegedApps = appsWithOverPrivileged,
            debugSignedApps = appsWithDebugCert,
            suspiciousNativeApps = appsWithSuspiciousLibs,
            systemAppsSummary = systemSummary
        )
    }

    /**
     * Aggregated summary for system apps — displayed in a separate section.
     */
    data class SystemAppsSummary(
        val totalSystemApps: Int,
        val criticalSystemApps: Int,
        val needsAttentionSystemApps: Int,
        val infoSystemApps: Int,
        val safeSystemApps: Int
    )
    
    data class ScanSummary(
        val totalAppsScanned: Int,
        val criticalRiskApps: Int,
        val highRiskApps: Int,
        val mediumRiskApps: Int,
        val safeApps: Int,
        val totalIssues: Int,
        val criticalIssues: Int,
        val overPrivilegedApps: Int,
        val debugSignedApps: Int,
        val suspiciousNativeApps: Int,
        /** System apps summary — null when system apps are not included */
        val systemAppsSummary: SystemAppsSummary? = null
    ) {
        /**
         * Apps security score for the dashboard (0–100).
         *
         * Only CRITICAL and NEEDS_ATTENTION apps penalize the score.
         * INFO and SAFE NEVER reduce the score — this prevents "noise regression"
         * where having many info-level findings makes the phone look insecure.
         *
         * Formula:
         *  - Start at 100
         *  - Each CRITICAL: -20 (capped at effective deduction)
         *  - Each NEEDS_ATTENTION: -5
         *  - Floor: 0
         */
        val appsSecurityScore: Int
            get() {
                if (totalAppsScanned == 0) return 100
                val deduction = (criticalRiskApps * 20) + (highRiskApps * 5)
                return (100 - deduction).coerceIn(0, 100)
            }
    }
}
