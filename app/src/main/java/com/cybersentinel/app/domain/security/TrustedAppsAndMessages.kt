package com.cybersentinel.app.domain.security

/**
 * Trusted Apps Whitelist & Human-Readable Interpretation
 * 
 * PRODUCT RULES (v2 — Evidence-based trust):
 * - Whitelist = (packageName + signing cert SHA-256) — NIKDY jen packageName
 * - Whitelist NENÍ imunita — pouze snížení váhy soft findings
 * - Hard findings (debug cert, baseline mismatch…) NIKDY nepotlačí
 * - Supports key rotation: multiple cert digests per app
 * - Provides APIs for TrustEvidenceEngine (getVerifiedAppCerts, matchDeveloperCert)
 */

/**
 * Secure whitelist requiring BOTH packageName AND SHA-256 certificate fingerprint.
 * Now supports:
 * - Multiple cert digests per app (for key rotation)
 * - Structured developer cert entries with metadata
 * - APIs consumed by TrustEvidenceEngine
 */
object TrustedAppsWhitelist {

    // ══════════════════════════════════════════════════════════
    //  Trust domains — separates signing authority contexts
    // ══════════════════════════════════════════════════════════

    /**
     * Signing authority domain for a package.
     *
     * The same package prefix (e.g. "com.google.") can be signed by
     * completely different keys depending on whether it is a Play Store
     * app, a platform component, or an updatable APEX module.
     * Comparing an APEX cert against a Play Store cert is meaningless
     * and produces false-positive SIGNATURE_MISMATCH findings.
     *
     * TrustDomain tells the scanner **which key set** to compare against
     * — or whether comparison is even meaningful.
     */
    enum class TrustDomain {
        /** User-space app signed via Google Play App Signing / third-party store */
        PLAY_SIGNED,
        /** Signed with the device platform key (sharedUserId=android, framework) */
        PLATFORM_SIGNED,
        /** Updatable mainline module delivered via /apex/ */
        APEX_MODULE,
        /** OEM/vendor partition component (signed with OEM key, not platform) */
        OEM_VENDOR,
        /** Cannot determine signing domain */
        UNKNOWN
    }

    /**
     * Classify the expected signer domain for a package.
     *
     * This does NOT look at the actual cert — it infers the *expected*
     * signing authority from the package's install location, flags and
     * partition.  The scanner uses this to decide whether a cert-vs-
     * whitelist comparison is even meaningful.
     */
    fun classifySignerDomain(
        isSystemApp: Boolean,
        isApex: Boolean,
        isPlatformSigned: Boolean,
        partition: TrustEvidenceEngine.AppPartition,
        sourceDir: String? = null
    ): TrustDomain = when {
        // APEX modules: dedicated module key, never matches Play cert
        isApex || sourceDir?.startsWith("/apex/") == true -> TrustDomain.APEX_MODULE
        // Platform-signed (sharedUserId=android): platform key
        isPlatformSigned -> TrustDomain.PLATFORM_SIGNED
        // Vendor / product partition but NOT platform-signed: OEM key
        isSystemApp && partition in setOf(
            TrustEvidenceEngine.AppPartition.VENDOR,
            TrustEvidenceEngine.AppPartition.PRODUCT
        ) -> TrustDomain.OEM_VENDOR
        // System app on /system partition but not platform-signed:
        // could be Google-signed system app (GMS) — still not Play cert
        isSystemApp && partition == TrustEvidenceEngine.AppPartition.SYSTEM -> TrustDomain.PLATFORM_SIGNED
        // System app with unknown partition (emulator / APEX fallback)
        isSystemApp -> TrustDomain.PLATFORM_SIGNED
        // User-space app (installed from store or sideloaded)
        else -> TrustDomain.PLAY_SIGNED
    }

    /**
     * Is it expected that this package's cert does NOT match the Play Store
     * developer whitelist?
     *
     * Returns `true` when cert-vs-whitelist comparison is meaningless
     * (platform / APEX / OEM domain).  A mismatch in these domains is
     * normal and should NOT produce a HARD finding.
     */
    fun isExpectedSignerMismatch(domain: TrustDomain): Boolean =
        domain != TrustDomain.PLAY_SIGNED && domain != TrustDomain.UNKNOWN

    /**
     * Detect partition / sourceDir anomalies that indicate a potentially
     * tampered system component.
     *
     * Returns a human-readable anomaly description, or `null` if clean.
     */
    fun detectPartitionAnomaly(
        packageName: String,
        isSystemApp: Boolean,
        sourceDir: String?,
        partition: TrustEvidenceEngine.AppPartition
    ): String? {
        if (!isSystemApp) return null

        // System app whose APK lives in /data/app → may have been overlaid
        // by a sideloaded version (common attack vector).
        if (sourceDir?.startsWith("/data/app") == true) {
            return "Systémová komponenta $packageName běží z /data/app místo systémového oddílu — " +
                    "může jít o neautorizovanou náhradu"
        }

        // FLAG_SYSTEM set but partition is DATA → suspicious
        if (partition == TrustEvidenceEngine.AppPartition.DATA) {
            return "Systémová komponenta $packageName je na datovém oddílu — " +
                    "neočekávané umístění"
        }

        return null
    }

    // ──────────────────────────────────────────────────────────
    //  Developer certs (prefix-based matching — PLAY_SIGNED domain only)
    // ──────────────────────────────────────────────────────────

    data class DeveloperEntry(
        val name: String,
        /** All known cert digests (current + historical for rotation) */
        val certDigests: Set<String>,
        /** Package prefixes this developer owns */
        val packagePrefixes: Set<String>,
        /**
         * Trust domain this entry applies to.  Default = PLAY_SIGNED.
         * Cert comparison is only meaningful when the app's actual domain
         * matches this entry's domain.
         */
        val domain: TrustDomain = TrustDomain.PLAY_SIGNED
    )

    private val trustedDevelopers = listOf(
        // Google Play-signed apps (GMS, Play Store apps)
        // NOTE: com.android.* prefix is intentionally NOT listed here.
        // System/APEX packages under com.android.* are PLATFORM_SIGNED or
        // APEX_MODULE — comparing them against this Play cert is wrong.
        DeveloperEntry(
            name = "Google",
            certDigests = setOf(
                "38918A453D07199354F8B19AF05EC6562CED5788"
                // Add rotated/historical Google certs here
            ),
            packagePrefixes = setOf("com.google."),
            domain = TrustDomain.PLAY_SIGNED
        ),
        DeveloperEntry(
            name = "Meta",
            certDigests = setOf(
                "A4B94B07E5D7D8E3E7D5B5B5B5B5B5B5B5B5B5B5"
            ),
            packagePrefixes = setOf("com.facebook.", "com.instagram.", "com.whatsapp", "com.meta.")
        ),
        DeveloperEntry(
            name = "Microsoft",
            certDigests = setOf(
                "C3D3E3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3"
            ),
            packagePrefixes = setOf("com.microsoft.")
        ),
        DeveloperEntry(
            name = "Samsung",
            certDigests = setOf(
                "34DF0E7A9F1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D"
            ),
            packagePrefixes = setOf("com.samsung.", "com.sec.android.")
        )
    )

    // ──────────────────────────────────────────────────────────
    //  Verified apps (exact package match, multiple certs for rotation)
    // ──────────────────────────────────────────────────────────

    /**
     * Key = package name, Value = set of allowed cert digest prefixes.
     * Multiple entries support key rotation — ANY of the certs is valid.
     *
     * Note: Replace placeholder fingerprints with real ones from APK analysis
     */
    private val verifiedApps: Map<String, Set<String>> = mapOf(
        // Czech Banks
        "cz.airbank.android" to setOf("AIR1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B"),
        "cz.csob.smartbanking" to setOf("CSOB1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "cz.csas.georgego" to setOf("CSAS1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "cz.kb.mobilebanking" to setOf("KB001B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "eu.inmite.prj.rb.mobilebanking" to setOf("RB001B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"),
        "cz.fio.ib2" to setOf("FIO01B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "cz.moneta.smartbanka" to setOf("MONE1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        
        // Major apps (can have multiple certs for rotation)
        "com.spotify.music" to setOf("SPOT1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.netflix.mediaclient" to setOf("NETF1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8"),
        "com.twitter.android" to setOf("TWIT1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.snapchat.android" to setOf("SNAP1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "org.telegram.messenger" to setOf("TELE1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.discord" to setOf("DISC1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.viber.voip" to setOf("VIBE1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.dropbox.android" to setOf("DROP1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "org.mozilla.firefox" to setOf("MOZI1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.brave.browser" to setOf("BRAV1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A"),
        "com.duckduckgo.mobile.android" to setOf("DUCK1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8")
    )

    // ──────────────────────────────────────────────────────────
    //  APIs for TrustEvidenceEngine
    // ──────────────────────────────────────────────────────────

    /**
     * Get all known cert digests for a verified app (supports rotation).
     * Returns null if the app is not in the verified list.
     */
    fun getVerifiedAppCerts(packageName: String): Set<String>? {
        return verifiedApps[packageName]
    }

    /**
     * Result of matching a package against developer cert entries
     */
    data class DeveloperCertMatch(
        val developerName: String,
        val expectedCert: String,
        val certMatches: Boolean,
        /** The trust domain of the matching entry */
        val entryDomain: TrustDomain = TrustDomain.PLAY_SIGNED
    )

    /**
     * Match a package name against developer cert entries.
     * Returns null if package doesn't match any developer prefix.
     *
     * When [callerDomain] is provided, only entries whose domain matches
     * are considered.  This prevents comparing a PLATFORM_SIGNED app's
     * cert against a PLAY_SIGNED entry (which would always "mismatch").
     */
    fun matchDeveloperCert(
        packageName: String,
        certPrefix: String,
        callerDomain: TrustDomain? = null
    ): DeveloperCertMatch? {
        for (dev in trustedDevelopers) {
            val matchesPrefix = dev.packagePrefixes.any { packageName.startsWith(it) }
            if (matchesPrefix) {
                // If caller specified a domain, skip entries from different domains
                if (callerDomain != null && dev.domain != callerDomain) continue
                val certMatches = dev.certDigests.any { knownCert ->
                    certPrefix.startsWith(knownCert) || knownCert.startsWith(certPrefix)
                }
                return DeveloperCertMatch(
                    developerName = dev.name,
                    expectedCert = dev.certDigests.first(), // Primary cert
                    certMatches = certMatches,
                    entryDomain = dev.domain
                )
            }
        }
        return null
    }

    // ──────────────────────────────────────────────────────────
    //  Legacy verification API (still used by AppSecurityScanner for now)
    // ──────────────────────────────────────────────────────────

    data class TrustVerification(
        val isTrusted: Boolean,
        val reason: TrustReason,
        val developerName: String?
    )
    
    enum class TrustReason {
        VERIFIED_DEVELOPER_CERT,
        VERIFIED_APP_CERT,
        UNKNOWN_CERT,
        UNKNOWN_PACKAGE
    }

    fun verifyTrustedApp(
        packageName: String,
        certSha256: String,
        signerDomain: TrustDomain = TrustDomain.PLAY_SIGNED
    ): TrustVerification {
        val certPrefix = certSha256.take(40).uppercase()
        
        // 1. Check individual verified apps (now with rotation support)
        val appCerts = verifiedApps[packageName]
        if (appCerts != null) {
            val matches = appCerts.any { knownDigest ->
                certPrefix.startsWith(knownDigest) || knownDigest.startsWith(certPrefix)
            }
            return if (matches) {
                TrustVerification(true, TrustReason.VERIFIED_APP_CERT, packageName)
            } else {
                TrustVerification(false, TrustReason.UNKNOWN_CERT, null)
            }
        }
        
        // 2. Check developer certificate + package prefix
        //    Pass signerDomain so non-PLAY domains skip PLAY-only entries
        val devMatch = matchDeveloperCert(packageName, certPrefix, signerDomain)
        if (devMatch != null) {
            return if (devMatch.certMatches) {
                TrustVerification(true, TrustReason.VERIFIED_DEVELOPER_CERT, devMatch.developerName)
            } else {
                TrustVerification(false, TrustReason.UNKNOWN_CERT, null)
            }
        }
        
        // 3. Not in whitelist
        return TrustVerification(false, TrustReason.UNKNOWN_PACKAGE, null)
    }

    // ──────────────────────────────────────────────────────────
    //  Finding downgrade (legacy — will be replaced by TrustRiskModel)
    // ──────────────────────────────────────────────────────────

    /**
     * DEPRECATED: Use TrustRiskModel for proper hard/soft finding classification.
     * Kept for backward compatibility during migration.
     */
    fun shouldDowngradeFinding(
        packageName: String, 
        certSha256: String,
        findingType: FindingType
    ): Boolean {
        val verification = verifyTrustedApp(packageName, certSha256)
        if (!verification.isTrusted) return false
        
        return when (findingType) {
            // SOFT findings — trust CAN downgrade
            FindingType.OVER_PRIVILEGED -> true
            FindingType.EXPORTED_COMPONENTS -> true
            FindingType.SUSPICIOUS_NATIVE_LIB -> true
            // HARD findings — trust NEVER downgrades
            FindingType.OLD_TARGET_SDK -> false
            FindingType.DEBUG_SIGNATURE -> false
        }
    }
    
    enum class FindingType {
        OVER_PRIVILEGED,
        EXPORTED_COMPONENTS,
        OLD_TARGET_SDK,
        DEBUG_SIGNATURE,
        SUSPICIOUS_NATIVE_LIB
    }
}

/**
 * Human-readable message generator for app security findings.
 * Converts technical findings into simple, actionable sentences.
 */
object HumanReadableMessages {
    
    /**
     * Generate user-friendly title and description for permission issues
     */
    fun forOverPrivileged(appName: String, criticalPermCount: Int): UserMessage {
        return UserMessage(
            title = "Nadměrná oprávnění",
            headline = "$appName má více oprávnění, než potřebuje",
            description = "Tato aplikace požaduje přístup k $criticalPermCount citlivým funkcím vašeho telefonu, " +
                    "což je více, než byste od aplikace tohoto typu očekávali.",
            impact = "Aplikace může sbírat data, která ke své funkci nepotřebuje. " +
                    "Vaše soukromí může být ohroženo.",
            actionLabel = "Zkontrolovat oprávnění",
            severity = Severity.MEDIUM
        )
    }
    
    fun forDebugSignature(appName: String): UserMessage {
        return UserMessage(
            title = "Neoficiální verze",
            headline = "$appName může být upravená verze",
            description = "Tato aplikace je podepsána vývojářským certifikátem, " +
                    "což znamená, že nepochází z oficiálního obchodu.",
            impact = "Upravené aplikace mohou obsahovat škodlivý kód. " +
                    "Doporučujeme stáhnout aplikaci z Google Play.",
            actionLabel = "Přeinstalovat z Play Store",
            severity = Severity.HIGH
        )
    }
    
    fun forOldAndroid(appName: String, targetSdk: Int, androidVersion: String): UserMessage {
        val severity = if (targetSdk < 26) Severity.HIGH else Severity.MEDIUM
        
        return UserMessage(
            title = "Zastaralá aplikace",
            headline = "$appName je navržena pro starší Android",
            description = "Tato aplikace cílí na Android $androidVersion a nemusí " +
                    "respektovat moderní bezpečnostní omezení vašeho telefonu.",
            impact = "Starší aplikace mohou obcházet oprávnění a přistupovat " +
                    "k datům způsobem, který novější Android blokuje.",
            actionLabel = "Zkontrolovat aktualizaci",
            severity = severity
        )
    }
    
    fun forSuspiciousNativeCode(appName: String, libraryHint: String): UserMessage {
        return UserMessage(
            title = "Podezřelý kód",
            headline = "$appName obsahuje neobvyklý kód",
            description = "Tato aplikace obsahuje komponenty, které jsou běžně " +
                    "používány nástroji pro obcházení zabezpečení telefonu.",
            impact = "Tento typ kódu se někdy používá k získání root přístupu " +
                    "nebo ke skrývání aktivit před bezpečnostními nástroji.",
            actionLabel = "Zvážit odinstalaci",
            severity = Severity.HIGH,
            technicalDetail = "Detekováno: $libraryHint"
        )
    }
    
    fun forExportedComponents(appName: String, componentCount: Int): UserMessage {
        return UserMessage(
            title = "Otevřené rozhraní",
            headline = "$appName může být ovládána jinými aplikacemi",
            description = "Tato aplikace má $componentCount nechráněných vstupních bodů, " +
                    "které mohou využít jiné aplikace ve vašem telefonu.",
            impact = "Škodlivá aplikace by mohla spouštět části této aplikace " +
                    "bez vašeho vědomí.",
            actionLabel = "Zkontrolovat aktualizaci",
            severity = Severity.LOW // Usually not critical for users
        )
    }
    
    fun forCriticalPermission(appName: String, permissionName: String, permissionDescription: String): UserMessage {
        return UserMessage(
            title = permissionName,
            headline = "$appName má přístup k: $permissionName",
            description = permissionDescription,
            impact = "Zvažte, zda tato aplikace skutečně potřebuje tento přístup ke své funkci.",
            actionLabel = "Spravovat oprávnění",
            severity = Severity.MEDIUM
        )
    }
    
    /**
     * Severity levels for user messages
     */
    enum class Severity {
        LOW,      // Informational, user can ignore
        MEDIUM,   // Worth reviewing
        HIGH      // Should take action
    }
    
    data class UserMessage(
        val title: String,
        val headline: String,
        val description: String,
        val impact: String,
        val actionLabel: String,
        val severity: Severity,
        val technicalDetail: String? = null
    )
}

/**
 * Risk category labels for app cards - user-friendly descriptions.
 * Now supports both legacy RiskLevel labels and new 4-state verdict labels.
 */
object RiskLabels {
    
    fun getLabel(riskLevel: AppSecurityScanner.RiskLevel): RiskLabel {
        return when (riskLevel) {
            AppSecurityScanner.RiskLevel.CRITICAL -> RiskLabel(
                badge = "Vyžaduje pozornost",
                color = 0xFFF44336,
                shortDescription = "Tato aplikace vykazuje neobvyklé chování"
            )
            AppSecurityScanner.RiskLevel.HIGH -> RiskLabel(
                badge = "Ke kontrole",
                color = 0xFFFF9800,
                shortDescription = "Doporučujeme zkontrolovat nastavení této aplikace"
            )
            AppSecurityScanner.RiskLevel.MEDIUM -> RiskLabel(
                badge = "Informace",
                color = 0xFF2196F3,
                shortDescription = "Má přístup k některým funkcím"
            )
            AppSecurityScanner.RiskLevel.LOW -> RiskLabel(
                badge = "V pořádku",
                color = 0xFF4CAF50,
                shortDescription = "Žádné významné problémy"
            )
            AppSecurityScanner.RiskLevel.NONE -> RiskLabel(
                badge = "Bezpečná",
                color = 0xFF4CAF50,
                shortDescription = "Aplikace splňuje bezpečnostní standardy"
            )
        }
    }
    
    /**
     * New 4-state verdict labels (primary system)
     */
    fun getVerdictLabel(verdict: TrustRiskModel.EffectiveRisk): RiskLabel {
        return when (verdict) {
            TrustRiskModel.EffectiveRisk.CRITICAL -> RiskLabel(
                badge = "Vyžaduje pozornost",
                color = 0xFFF44336,
                shortDescription = "Tato aplikace vykazuje neobvyklé chování"
            )
            TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION -> RiskLabel(
                badge = "Ke kontrole",
                color = 0xFFFF9800,
                shortDescription = "Doporučujeme zkontrolovat"
            )
            TrustRiskModel.EffectiveRisk.INFO -> RiskLabel(
                badge = "Informace",
                color = 0xFF2196F3,
                shortDescription = "Má přístup k některým funkcím zařízení"
            )
            TrustRiskModel.EffectiveRisk.SAFE -> RiskLabel(
                badge = "Bezpečná",
                color = 0xFF4CAF50,
                shortDescription = "Aplikace splňuje bezpečnostní standardy"
            )
        }
    }
    
    data class RiskLabel(
        val badge: String,
        val color: Long,
        val shortDescription: String
    )
}

/**
 * App category detection for contextual permission evaluation.
 * 
 * Key design: permissions that are "expected" for a category are NOT alarming.
 * Camera app having CAMERA is normal. Calculator having CAMERA is suspicious.
 * But "suspicious" alone is just INFO for unknown apps, not an alarm.
 */
object AppCategoryDetector {
    
    fun detectCategory(packageName: String, appName: String): AppCategory {
        val nameLower = appName.lowercase()
        val pkgLower = packageName.lowercase()
        
        return when {
            // ── System-level categories (detected by well-known system package patterns) ──
            // Telephony / Telecom framework
            pkgLower.contains("telecom") || pkgLower.contains("telephony") ||
            pkgLower == "com.android.phone" || pkgLower == "com.android.server.telecom" ||
            pkgLower.contains("carrierservices") || pkgLower.contains("carrier") ||
            pkgLower.contains("simappdiag") -> AppCategory.SYSTEM_TELECOM

            // System messaging (built-in SMS/MMS)
            pkgLower == "com.android.mms" || pkgLower == "com.google.android.apps.messaging" ||
            pkgLower.contains("messaging") && pkgLower.startsWith("com.android") ||
            pkgLower.contains("messaging") && pkgLower.startsWith("com.google.android") ->
                AppCategory.SYSTEM_MESSAGING

            // System UI / framework
            pkgLower == "com.android.systemui" || pkgLower == "android" ||
            pkgLower == "com.android.providers.settings" ||
            pkgLower.contains("setupwizard") || pkgLower.contains("companiondevicemanager") ||
            pkgLower.contains("permissioncontroller") || pkgLower.contains("packageinstaller") ->
                AppCategory.SYSTEM_FRAMEWORK

            // Connectivity stack (WiFi, Bluetooth, NFC, tethering)
            pkgLower.contains("bluetooth") || pkgLower.contains("wifi") ||
            pkgLower.contains("tethering") || pkgLower.contains("nfc") ||
            pkgLower.contains("connectivity") || pkgLower.contains("networkstack") ->
                AppCategory.SYSTEM_CONNECTIVITY

            // VPN apps
            pkgLower.contains("vpn") || nameLower.contains("vpn") ||
            pkgLower.contains("wireguard") || pkgLower.contains("openvpn") ||
            pkgLower.contains("nordvpn") || pkgLower.contains("expressvpn") ||
            pkgLower.contains("tunnelbear") || pkgLower.contains("surfshark") -> AppCategory.VPN

            // Banking
            pkgLower.contains("bank") || nameLower.contains("bank") ||
            pkgLower.contains("finance") || nameLower.contains("spořen") ||
            pkgLower.contains("moneta") || pkgLower.contains("csob") ||
            pkgLower.contains("csas") || pkgLower.contains("fio.ib") -> AppCategory.BANKING
            
            // Messaging
            pkgLower.contains("messenger") || pkgLower.contains("chat") ||
            pkgLower.contains("whatsapp") || pkgLower.contains("telegram") ||
            pkgLower.contains("viber") || pkgLower.contains("signal") ||
            pkgLower.contains("discord") || nameLower.contains("messenger") -> AppCategory.MESSAGING
            
            // Social
            pkgLower.contains("facebook") || pkgLower.contains("instagram") ||
            pkgLower.contains("twitter") || pkgLower.contains("tiktok") ||
            pkgLower.contains("snapchat") || pkgLower.contains("reddit") -> AppCategory.SOCIAL
            
            // Navigation
            pkgLower.contains("maps") || pkgLower.contains("navigation") ||
            pkgLower.contains("waze") || nameLower.contains("mapy") ||
            pkgLower.contains("sygic") -> AppCategory.NAVIGATION
            
            // Camera / Photo
            pkgLower.contains("camera") || pkgLower.contains("photo") ||
            nameLower.contains("kamera") || nameLower.contains("foto") -> AppCategory.CAMERA
            
            // Fitness / Health
            pkgLower.contains("fitness") || pkgLower.contains("health") ||
            pkgLower.contains("sport") || nameLower.contains("zdraví") ||
            pkgLower.contains("strava") || pkgLower.contains("fitbit") -> AppCategory.FITNESS
            
            // Browser
            pkgLower.contains("browser") || pkgLower.contains("chrome") ||
            pkgLower.contains("firefox") || pkgLower.contains("brave") ||
            pkgLower.contains("opera") || pkgLower.contains("edge") ||
            pkgLower.contains("duckduckgo") || pkgLower.contains("webview") -> AppCategory.BROWSER
            
            // Phone / Dialer / Contacts
            pkgLower.contains("dialer") || pkgLower.contains("contacts") ||
            pkgLower.contains("incallui") || pkgLower.contains("phone") -> AppCategory.PHONE_DIALER
            
            // Security
            pkgLower.contains("security") || pkgLower.contains("antivirus") ||
            pkgLower.contains("malware") || pkgLower.contains("lookout") ||
            pkgLower.contains("cybersentinel") -> AppCategory.SECURITY
            
            // Launcher
            pkgLower.contains("launcher") || pkgLower.contains("home") ||
            nameLower.contains("launcher") -> AppCategory.LAUNCHER
            
            // Accessibility tools
            pkgLower.contains("accessibility") || pkgLower.contains("talkback") ||
            nameLower.contains("usnadnění") -> AppCategory.ACCESSIBILITY_TOOL
            
            // Games
            pkgLower.contains("game") || nameLower.contains("hra") -> AppCategory.GAME
            
            // Utilities / Simple apps
            pkgLower.contains("calculator") || pkgLower.contains("flashlight") ||
            pkgLower.contains("compass") || pkgLower.contains("qr") ||
            pkgLower.contains("barcode") || pkgLower.contains("clock") ||
            pkgLower.contains("alarm") || pkgLower.contains("timer") ||
            pkgLower.contains("note") || pkgLower.contains("memo") ||
            pkgLower.contains("todo") || pkgLower.contains("ruler") ||
            nameLower.contains("kalkulačka") || nameLower.contains("svítilna") ||
            nameLower.contains("kompas") -> AppCategory.UTILITY
            
            // Keyboard / Input
            pkgLower.contains("keyboard") || pkgLower.contains("inputmethod") ||
            pkgLower.contains("gboard") || pkgLower.contains("swiftkey") -> AppCategory.KEYBOARD
            
            else -> AppCategory.OTHER
        }
    }
    
    /**
     * App categories with expected permissions.
     * Permissions listed here are NOT alarming for apps in that category.
     */
    enum class AppCategory(val label: String, val expectedPermissions: Set<String>) {
        // ── System categories (ROM components) ──
        SYSTEM_TELECOM("Telecom systém", setOf(
            "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS", "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS", "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        )),
        SYSTEM_MESSAGING("Systémové zprávy", setOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_MMS",
            "android.permission.READ_CONTACTS", "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"
        )),
        SYSTEM_FRAMEWORK("Systémový framework", setOf(
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA", "android.permission.RECORD_AUDIO"
        )),
        SYSTEM_CONNECTIVITY("Systémová konektivita", setOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.ACCESS_WIFI_STATE", "android.permission.CHANGE_WIFI_STATE",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BIND_VPN_SERVICE"
        )),

        // ── User categories ──
        BANKING("Bankovnictví", setOf(
            "android.permission.CAMERA",  // QR codes, check deposit
            "android.permission.ACCESS_FINE_LOCATION",  // Branch finder
            "android.permission.USE_BIOMETRIC"
        )),
        MESSAGING("Komunikace", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        )),
        SOCIAL("Sociální sítě", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        )),
        NAVIGATION("Navigace", setOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO"  // Voice commands
        )),
        CAMERA("Fotografie", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION"  // Geo-tagging
        )),
        FITNESS("Zdraví a fitness", setOf(
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.BLUETOOTH_CONNECT"
        )),
        BROWSER("Prohlížeč", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE"
        )),
        PHONE_DIALER("Telefon", setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA"
        )),
        VPN("VPN", setOf(
            "android.permission.BIND_VPN_SERVICE"
        )),
        SECURITY("Bezpečnost", setOf(
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.POST_NOTIFICATIONS"
        )),
        LAUNCHER("Launcher", setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION"
        )),
        ACCESSIBILITY_TOOL("Usnadnění", setOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        )),
        KEYBOARD("Klávesnice", setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.VIBRATE"
        )),
        GAME("Hry", setOf()),
        UTILITY("Nástroje", setOf()),
        OTHER("Ostatní", setOf())
    }
    
    /**
     * Check if a permission is expected for the app category
     */
    fun isPermissionExpected(category: AppCategory, permission: String): Boolean {
        return permission in category.expectedPermissions
    }
    
    /**
     * Get permissions that are unexpected for the app category.
     * These are candidates for "unexplained capability" — but still just info, not alarm.
     */
    fun getUnexpectedPermissions(
        category: AppCategory,
        grantedPermissions: List<String>
    ): List<String> {
        return grantedPermissions.filter { it !in category.expectedPermissions }
    }
}
