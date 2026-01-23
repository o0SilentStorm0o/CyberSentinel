package com.cybersentinel.app.domain.scoring

import com.cybersentinel.app.data.kev.KevCatalog
import com.cybersentinel.app.domain.device.DeviceProfile
import com.cybersentinel.app.domain.model.CveItem

data class RelevantCve(
    val item: CveItem, 
    val score: Int, 
    val tags: List<String>
)

// Original synchronous version (for backward compatibility)
fun relevance(item: CveItem, profile: DeviceProfile): RelevantCve {
    val text = (item.id + " " + item.summary).lowercase()
    var score = 0
    val tags = mutableListOf<String>()

    // Základní Android relevance
    if ("android" in text) { 
        score += 5
        tags += "OS" 
    }

    // OEM specifické
    if (profile.manufacturer.lowercase() in text || profile.model.lowercase() in text) { 
        score += 4
        tags += "OEM" 
    }

    // Pixel specific
    if ("pixel" in text && profile.manufacturer.equals("google", true)) { 
        score += 3
        tags += "Pixel" 
    }

    // SoC/Kernel komponenty
    if (listOf("qualcomm", "mediatek", "exynos", "mali", "adreno", "kernel").any { it in text }) { 
        score += 2
        tags += "SoC/Kernel" 
    }

    // Browser komponenty
    if (listOf("chrome", "chromium", "webview").any { it in text }) { 
        score += 3
        tags += "Browser" 
    }

    // Rádiové komponenty
    if (listOf("bluetooth", "wifi", "nfc").any { it in text }) { 
        score += 1
        tags += "Radio" 
    }

    // Android verze specifické
    val osHints = mapOf(
        34 to "android 14", 
        33 to "android 13", 
        32 to "android 12l", 
        31 to "android 12", 
        30 to "android 11"
    )
    osHints[profile.sdkInt]?.let { 
        if (it in text) { 
            score += 2
            tags += it 
        } 
    }

    return RelevantCve(item, score, tags.distinct())
}

// Enhanced version with KEV support
suspend fun relevanceWithKev(item: CveItem, profile: DeviceProfile, kevCatalog: KevCatalog): RelevantCve {
    // Start with base scoring
    var relevantCve = relevance(item, profile)
    var score = relevantCve.score
    val tags = relevantCve.tags.toMutableList()
    
    // KEV (Known Exploited Vulnerabilities) boost
    if (kevCatalog.isKev(item.id)) {
        score += 6
        tags += "🔥 KEV"
    }
    
    // Exploitability boost: remote no-auth
    item.summary.lowercase().let { text ->
        if (("remote" in text && "no auth" in text) || 
            ("network" in text && "unauthenticated" in text)) {
            score += 2
            tags += "Remote"
        }
    }
    
    // Installed app match (basic heuristics)
    val installedApps = mapOf(
        "chrome" to "Browser",
        "webview" to "Browser", 
        "gboard" to "Keyboard",
        "photos" to "Google App",
        "sheets" to "Google App",
        "docs" to "Google App"
    )
    
    installedApps.forEach { (app, category) ->
        if (app in item.summary.lowercase()) {
            score += 4
            tags += "App: $category"
        }
    }
    
    return RelevantCve(item, score, tags.distinct())
}