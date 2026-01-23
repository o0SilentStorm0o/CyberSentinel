package com.cybersentinel.ui.screens.qr

import android.net.Uri
import java.net.IDN
import java.net.MalformedURLException
import java.net.URL

/**
 * PhishGuard URL analyzer pro detekci phishing URLs
 */
class PhishGuardAnalyzer {
    
    companion object {
        // Podezřelé TLD (Top Level Domains)
        private val SUSPICIOUS_TLDS = setOf(
            "tk", "ml", "ga", "cf", // Freenom free domains
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", // URL shorteners
            "bit.do", "short.link", "ow.ly"
        )
        
        // Známé URL shortenery
        private val URL_SHORTENERS = setOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "bit.do", "short.link", "tiny.cc", "is.gd", "buff.ly"
        )
        
        // Podezřelé klíčová slova v doménách
        private val SUSPICIOUS_KEYWORDS = setOf(
            "paypal", "amazon", "google", "facebook", "microsoft",
            "apple", "netflix", "spotify", "instagram", "twitter",
            "bank", "secure", "login", "update", "verify",
            "account", "suspended", "confirm", "urgent"
        )
    }
    
    /**
     * Analyzuje URL a vrací risk score (0-100)
     */
    fun analyzeUrl(urlString: String): PhishingAnalysisResult {
        return try {
            val url = URL(urlString)
            val uri = Uri.parse(urlString)
            
            var riskScore = 0
            val warnings = mutableListOf<String>()
            
            // IDN/Punycode detekce
            val idnResult = checkIDN(url.host)
            if (idnResult.isIDN) {
                riskScore += 30
                warnings.add("Obsahuje mezinárodní znaky (IDN/Punycode): ${idnResult.decodedHost}")
            }
            
            // URL shortener detekce
            if (isUrlShortener(url.host)) {
                riskScore += 25
                warnings.add("URL shortener detected: ${url.host}")
            }
            
            // Suspicious TLD
            if (hasSuspiciousTLD(url.host)) {
                riskScore += 20
                warnings.add("Podezřelá doména TLD: ${url.host}")
            }
            
            // Suspicious keywords
            val suspiciousKeywords = findSuspiciousKeywords(url.host)
            if (suspiciousKeywords.isNotEmpty()) {
                riskScore += 25
                warnings.add("Podezřelá klíčová slova: ${suspiciousKeywords.joinToString(", ")}")
            }
            
            // Dlouhá doména (často sign of obfuscation)
            if (url.host.length > 50) {
                riskScore += 15
                warnings.add("Neobvykle dlouhá doména")
            }
            
            // Více subdomén
            val subdomainCount = url.host.split(".").size
            if (subdomainCount > 4) {
                riskScore += 10
                warnings.add("Mnoho subdomén ($subdomainCount)")
            }
            
            // HTTPS kontrola
            if (url.protocol != "https") {
                riskScore += 20
                warnings.add("Nezabezpečené HTTP spojení")
            }
            
            PhishingAnalysisResult(
                originalUrl = urlString,
                riskScore = minOf(riskScore, 100), // Cap at 100
                warnings = warnings,
                isIDN = idnResult.isIDN,
                decodedHost = idnResult.decodedHost,
                isShortener = isUrlShortener(url.host)
            )
            
        } catch (e: MalformedURLException) {
            PhishingAnalysisResult(
                originalUrl = urlString,
                riskScore = 50,
                warnings = listOf("Neplatný URL formát"),
                isIDN = false,
                decodedHost = null,
                isShortener = false
            )
        }
    }
    
    private fun checkIDN(host: String): IDNResult {
        return try {
            val asciiHost = IDN.toASCII(host)
            val unicodeHost = IDN.toUnicode(host)
            
            IDNResult(
                isIDN = asciiHost != host || unicodeHost != host,
                decodedHost = if (asciiHost != host) unicodeHost else null
            )
        } catch (e: Exception) {
            IDNResult(isIDN = false, decodedHost = null)
        }
    }
    
    private fun isUrlShortener(host: String): Boolean {
        return URL_SHORTENERS.any { shortener ->
            host.equals(shortener, ignoreCase = true) || host.endsWith(".$shortener")
        }
    }
    
    private fun hasSuspiciousTLD(host: String): Boolean {
        return SUSPICIOUS_TLDS.any { tld ->
            host.equals(tld, ignoreCase = true) || host.endsWith(".$tld")
        }
    }
    
    private fun findSuspiciousKeywords(host: String): List<String> {
        val lowerHost = host.lowercase()
        return SUSPICIOUS_KEYWORDS.filter { keyword ->
            lowerHost.contains(keyword)
        }
    }
}

/**
 * Výsledek analýzy phishing URL
 */
data class PhishingAnalysisResult(
    val originalUrl: String,
    val riskScore: Int, // 0-100
    val warnings: List<String>,
    val isIDN: Boolean,
    val decodedHost: String?,
    val isShortener: Boolean
) {
    val riskLevel: RiskLevel
        get() = when {
            riskScore >= 70 -> RiskLevel.HIGH
            riskScore >= 40 -> RiskLevel.MEDIUM
            riskScore >= 20 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
}

/**
 * IDN analýza result
 */
private data class IDNResult(
    val isIDN: Boolean,
    val decodedHost: String?
)

/**
 * Úroveň rizika
 */
enum class RiskLevel(val displayName: String) {
    SAFE("Bezpečné"),
    LOW("Nízké riziko"),
    MEDIUM("Střední riziko"), 
    HIGH("Vysoké riziko")
}