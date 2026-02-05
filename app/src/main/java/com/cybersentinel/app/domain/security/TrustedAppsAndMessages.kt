package com.cybersentinel.app.domain.security

/**
 * Trusted Apps Whitelist & Human-Readable Interpretation
 * 
 * This module ensures:
 * 1. Known legitimate apps don't get flagged as suspicious
 * 2. All findings are translated to user-friendly language
 * 3. Play Store policy compliance (no scareware)
 */

/**
 * Whitelist of known trusted package names from major developers.
 * These apps will have reduced sensitivity for certain checks to avoid false positives.
 */
object TrustedAppsWhitelist {
    
    // Major tech companies - these apps are legitimate even with broad permissions
    private val trustedPackages = setOf(
        // Google
        "com.google.android.gms",
        "com.google.android.apps.maps",
        "com.google.android.apps.photos",
        "com.google.android.youtube",
        "com.google.android.apps.docs",
        "com.google.android.apps.messaging",
        "com.google.android.dialer",
        "com.google.android.contacts",
        "com.google.android.calendar",
        "com.google.android.gm",
        "com.google.android.keep",
        "com.google.android.apps.fitness",
        "com.google.android.apps.translate",
        "com.google.android.apps.walletnfcrel",
        "com.android.chrome",
        "com.android.vending",
        
        // Meta
        "com.facebook.katana",
        "com.facebook.orca",
        "com.instagram.android",
        "com.whatsapp",
        "com.facebook.lite",
        
        // Microsoft
        "com.microsoft.office.outlook",
        "com.microsoft.teams",
        "com.microsoft.office.word",
        "com.microsoft.office.excel",
        "com.microsoft.office.powerpoint",
        "com.microsoft.skydrive",
        "com.microsoft.launcher",
        "com.microsoft.emmx",
        "com.microsoft.todos",
        
        // Samsung
        "com.samsung.android.messaging",
        "com.samsung.android.dialer",
        "com.samsung.android.contacts",
        "com.samsung.android.calendar",
        "com.samsung.android.email.provider",
        "com.samsung.android.app.notes",
        "com.samsung.android.samsungpass",
        "com.samsung.android.smartswitchassistant",
        
        // Other major apps
        "com.spotify.music",
        "com.netflix.mediaclient",
        "com.amazon.mShop.android.shopping",
        "com.twitter.android",
        "com.snapchat.android",
        "com.linkedin.android",
        "com.pinterest",
        "com.tiktok.android",
        "com.discord",
        "org.telegram.messenger",
        "com.viber.voip",
        "jp.naver.line.android",
        "com.zhiliaoapp.musically",
        
        // Banking (Czech)
        "cz.airbank.android",
        "cz.csob.smartbanking",
        "cz.csas.georgego",
        "cz.kb.mobilebanking",
        "eu.inmite.prj.rb.mobilebanking",
        "cz.fio.ib2",
        "cz.moneta.smartbanka",
        
        // Utilities
        "com.dropbox.android",
        "com.evernote",
        "com.adobe.reader",
        "org.mozilla.firefox",
        "com.opera.browser",
        "com.brave.browser",
        "com.duckduckgo.mobile.android"
    )
    
    // Package prefixes for trusted developers
    private val trustedPrefixes = listOf(
        "com.google.",
        "com.android.",
        "com.samsung.",
        "com.microsoft.",
        "com.facebook.",
        "com.meta.",
        "com.huawei.",
        "com.xiaomi.",
        "com.sec.android."
    )
    
    fun isTrustedApp(packageName: String): Boolean {
        if (packageName in trustedPackages) return true
        return trustedPrefixes.any { packageName.startsWith(it) }
    }
    
    /**
     * For trusted apps, certain findings should be downgraded or hidden
     */
    fun shouldDowngradeFinding(packageName: String, findingType: FindingType): Boolean {
        if (!isTrustedApp(packageName)) return false
        
        return when (findingType) {
            // Trusted apps legitimately need many permissions
            FindingType.OVER_PRIVILEGED -> true
            // Trusted apps often have exported components for integrations
            FindingType.EXPORTED_COMPONENTS -> true
            // Old SDK target might be for compatibility
            FindingType.OLD_TARGET_SDK -> false // Still warn about this
            // Debug signature is still concerning
            FindingType.DEBUG_SIGNATURE -> false
            // Native libs in trusted apps are OK
            FindingType.SUSPICIOUS_NATIVE_LIB -> true
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
