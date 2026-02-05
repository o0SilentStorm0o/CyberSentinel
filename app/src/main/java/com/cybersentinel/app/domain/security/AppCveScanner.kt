package com.cybersentinel.app.domain.security

import com.cybersentinel.app.data.repo.CveRepository
import com.cybersentinel.app.domain.model.CveItem
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Conservative App CVE Scanner
 * 
 * PRODUCT RULES:
 * - Mapovat jen jasně prokazatelné vazby na Android app/vendor
 * - NVD není přímo pro packageName → vyhnout se odhadům
 * - Vysoká jistota > množství nálezů
 * 
 * We ONLY match apps where we have HIGH CONFIDENCE mapping to CVE data:
 * 1. Chrome browser → cpe:2.3:a:google:chrome
 * 2. Android WebView → cpe:2.3:a:google:webview (affects all apps using WebView)
 * 3. System Android version → cpe:2.3:o:google:android
 * 
 * We DO NOT attempt to guess vendor/product from arbitrary packageNames.
 */
@Singleton
class AppCveScanner @Inject constructor(
    private val cveRepository: CveRepository
) {
    
    /**
     * Result of CVE scan for an app
     */
    data class AppCveResult(
        val packageName: String,
        val matchType: MatchType,
        val cves: List<CveItem>,
        val confidence: Confidence,
        val explanation: String
    )
    
    enum class MatchType {
        DIRECT_BROWSER,      // Chrome, Firefox, etc. - direct CVE match
        WEBVIEW_COMPONENT,   // App uses WebView - inherits WebView CVEs
        ANDROID_SYSTEM,      // System app - inherits Android OS CVEs
        NO_MATCH             // No reliable CVE source (we don't guess)
    }
    
    enum class Confidence {
        HIGH,    // Direct match with version - very reliable
        MEDIUM,  // Component-based match (e.g., uses WebView)
        LOW,     // Cannot reliably match - we skip these
        NONE     // No CVE data applicable
    }
    
    /**
     * High-confidence package → CPE mappings.
     * 
     * ONLY apps where we can reliably determine the CVE-relevant product.
     * Key: package name or prefix
     * Value: Triple(vendor, product, isPrefix)
     */
    private val highConfidenceMappings = mapOf(
        // Google Chrome - direct version match possible
        "com.android.chrome" to CpeMapping("google", "chrome", exact = true),
        
        // Mozilla Firefox
        "org.mozilla.firefox" to CpeMapping("mozilla", "firefox", exact = true),
        "org.mozilla.firefox_beta" to CpeMapping("mozilla", "firefox", exact = true),
        "org.mozilla.fenix" to CpeMapping("mozilla", "firefox", exact = true), // Firefox for Android
        
        // Brave Browser (Chromium-based)
        "com.brave.browser" to CpeMapping("brave", "browser", exact = true),
        
        // Samsung Browser (Chromium-based)
        "com.sec.android.app.sbrowser" to CpeMapping("samsung", "internet", exact = true),
        
        // Opera
        "com.opera.browser" to CpeMapping("opera", "opera_browser", exact = true),
        
        // Edge (Chromium-based)
        "com.microsoft.emmx" to CpeMapping("microsoft", "edge", exact = true),
        
        // DuckDuckGo
        "com.duckduckgo.mobile.android" to CpeMapping("duckduckgo", "privacy_browser", exact = true)
    )
    
    private data class CpeMapping(
        val vendor: String,
        val product: String,
        val exact: Boolean  // true = packageName must match exactly
    )
    
    /**
     * Scan an app for known CVEs.
     * 
     * Returns results ONLY for high-confidence matches.
     * Does NOT attempt to guess for unknown apps.
     */
    suspend fun scanAppForCves(
        packageName: String,
        versionName: String?,
        usesWebView: Boolean
    ): AppCveResult {
        
        // 1. Check high-confidence direct mappings (browsers, etc.)
        val directMapping = highConfidenceMappings[packageName]
        if (directMapping != null && versionName != null) {
            return scanWithDirectMapping(packageName, versionName, directMapping)
        }
        
        // 2. For apps using WebView, we can warn about WebView CVEs
        // (This is a component-level match, not app-specific)
        if (usesWebView) {
            return AppCveResult(
                packageName = packageName,
                matchType = MatchType.WEBVIEW_COMPONENT,
                cves = emptyList(), // WebView CVEs are shown separately at system level
                confidence = Confidence.MEDIUM,
                explanation = "Tato aplikace používá WebView. " +
                        "Zranitelnosti WebView jsou sledovány na úrovni systému."
            )
        }
        
        // 3. No reliable CVE source - we don't guess
        return AppCveResult(
            packageName = packageName,
            matchType = MatchType.NO_MATCH,
            cves = emptyList(),
            confidence = Confidence.NONE,
            explanation = "Pro tuto aplikaci nemáme spolehlivý zdroj CVE dat."
        )
    }
    
    private suspend fun scanWithDirectMapping(
        packageName: String,
        versionName: String,
        mapping: CpeMapping
    ): AppCveResult {
        // Parse version for CVE matching
        val majorVersion = extractMajorVersion(versionName)
        
        // Build CPE string for NVD query
        // Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        val cpePrefix = "cpe:2.3:a:${mapping.vendor}:${mapping.product}"
        
        return try {
            // Query NVD for this product
            val cves = cveRepository.searchCvesForProduct(
                vendor = mapping.vendor,
                product = mapping.product,
                version = majorVersion
            )
            
            AppCveResult(
                packageName = packageName,
                matchType = MatchType.DIRECT_BROWSER,
                cves = cves,
                confidence = Confidence.HIGH,
                explanation = if (cves.isNotEmpty()) {
                    "Nalezeno ${cves.size} známých zranitelností pro ${mapping.product} verze $majorVersion."
                } else {
                    "Žádné známé zranitelnosti pro ${mapping.product} verze $majorVersion."
                }
            )
        } catch (e: Exception) {
            AppCveResult(
                packageName = packageName,
                matchType = MatchType.DIRECT_BROWSER,
                cves = emptyList(),
                confidence = Confidence.MEDIUM,
                explanation = "Nepodařilo se ověřit CVE pro ${mapping.product}."
            )
        }
    }
    
    /**
     * Extract major version from version string.
     * Examples:
     * - "120.0.6099.43" → "120"
     * - "121.0" → "121"
     * - "v4.5.2" → "4"
     */
    private fun extractMajorVersion(versionName: String): String {
        // Remove leading 'v' if present
        val cleaned = versionName.trimStart('v', 'V')
        
        // Find first number sequence
        val majorMatch = Regex("^(\\d+)").find(cleaned)
        return majorMatch?.groupValues?.get(1) ?: versionName
    }
    
    /**
     * Get explanation for why we don't provide CVE data for most apps.
     * This is shown to users who ask why their app doesn't have CVE info.
     */
    fun getNoMatchExplanation(): String {
        return """
            Proč nemám CVE data pro tuto aplikaci?
            
            CVE databáze (NVD) sleduje zranitelnosti na úrovni software produktů, 
            ne jednotlivých Android aplikací. Spolehlivě můžeme mapovat pouze:
            
            • Webové prohlížeče (Chrome, Firefox, Edge...)
            • Systémové komponenty (WebView, Android OS)
            
            Pro ostatní aplikace bychom museli hádat, což by vedlo k falešným poplachům.
            Raději zobrazujeme méně nálezů s vysokou jistotou.
        """.trimIndent()
    }
}
