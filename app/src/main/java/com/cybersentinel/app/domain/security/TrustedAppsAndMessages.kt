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
    
    // ──────────────────────────────────────────────────────────
    //  Developer certs (prefix-based matching)
    // ──────────────────────────────────────────────────────────

    data class DeveloperEntry(
        val name: String,
        /** All known cert digests (current + historical for rotation) */
        val certDigests: Set<String>,
        /** Package prefixes this developer owns */
        val packagePrefixes: Set<String>
    )

    private val trustedDevelopers = listOf(
        DeveloperEntry(
            name = "Google",
            certDigests = setOf(
                "38918A453D07199354F8B19AF05EC6562CED5788"
                // Add rotated/historical Google certs here
            ),
            packagePrefixes = setOf("com.google.", "com.android.")
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
        val certMatches: Boolean
    )

    /**
     * Match a package name against developer cert entries.
     * Returns null if package doesn't match any developer prefix.
     */
    fun matchDeveloperCert(packageName: String, certPrefix: String): DeveloperCertMatch? {
        for (dev in trustedDevelopers) {
            val matchesPrefix = dev.packagePrefixes.any { packageName.startsWith(it) }
            if (matchesPrefix) {
                val certMatches = dev.certDigests.any { knownCert ->
                    certPrefix.startsWith(knownCert) || knownCert.startsWith(certPrefix)
                }
                return DeveloperCertMatch(
                    developerName = dev.name,
                    expectedCert = dev.certDigests.first(), // Primary cert
                    certMatches = certMatches
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

    fun verifyTrustedApp(packageName: String, certSha256: String): TrustVerification {
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
        val devMatch = matchDeveloperCert(packageName, certPrefix)
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
 * Risk category labels for app cards - user-friendly descriptions
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
                badge = "Upozornění",
                color = 0xFFFFEB3B,
                shortDescription = "Nalezeny drobné nedostatky"
            )
            AppSecurityScanner.RiskLevel.LOW -> RiskLabel(
                badge = "V pořádku",
                color = 0xFF4CAF50,
                shortDescription = "Žádné významné problémy"
            )
            AppSecurityScanner.RiskLevel.NONE -> RiskLabel(
                badge = "Bezpečná",
                color = 0xFF2196F3,
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
 * App category detection for better context
 */
object AppCategoryDetector {
    
    fun detectCategory(packageName: String, appName: String): AppCategory {
        val nameLower = appName.lowercase()
        val pkgLower = packageName.lowercase()
        
        return when {
            // Banking
            pkgLower.contains("bank") || nameLower.contains("bank") ||
            pkgLower.contains("finance") || nameLower.contains("spořen") -> AppCategory.BANKING
            
            // Messaging
            pkgLower.contains("messenger") || pkgLower.contains("chat") ||
            pkgLower.contains("whatsapp") || pkgLower.contains("telegram") ||
            pkgLower.contains("viber") || nameLower.contains("messenger") -> AppCategory.MESSAGING
            
            // Social
            pkgLower.contains("facebook") || pkgLower.contains("instagram") ||
            pkgLower.contains("twitter") || pkgLower.contains("tiktok") ||
            pkgLower.contains("snapchat") -> AppCategory.SOCIAL
            
            // Navigation
            pkgLower.contains("maps") || pkgLower.contains("navigation") ||
            pkgLower.contains("waze") || nameLower.contains("mapy") -> AppCategory.NAVIGATION
            
            // Camera / Photo
            pkgLower.contains("camera") || pkgLower.contains("photo") ||
            nameLower.contains("kamera") || nameLower.contains("foto") -> AppCategory.CAMERA
            
            // Fitness / Health
            pkgLower.contains("fitness") || pkgLower.contains("health") ||
            pkgLower.contains("sport") || nameLower.contains("zdraví") -> AppCategory.FITNESS
            
            // Games
            pkgLower.contains("game") || nameLower.contains("hra") -> AppCategory.GAME
            
            // Utilities
            pkgLower.contains("calculator") || pkgLower.contains("flashlight") ||
            pkgLower.contains("compass") || pkgLower.contains("qr") ||
            nameLower.contains("kalkulačka") || nameLower.contains("svítilna") -> AppCategory.UTILITY
            
            else -> AppCategory.OTHER
        }
    }
    
    enum class AppCategory(val label: String, val expectedPermissions: Set<String>) {
        BANKING("Bankovnictví", setOf()),
        MESSAGING("Komunikace", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS"
        )),
        SOCIAL("Sociální sítě", setOf(
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION"
        )),
        NAVIGATION("Navigace", setOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        )),
        CAMERA("Fotografie", setOf(
            "android.permission.CAMERA",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION"
        )),
        FITNESS("Zdraví a fitness", setOf(
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.ACCESS_FINE_LOCATION"
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
}
