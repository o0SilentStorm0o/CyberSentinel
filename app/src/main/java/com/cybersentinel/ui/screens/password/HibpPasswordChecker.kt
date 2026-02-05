package com.cybersentinel.ui.screens.password

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response as OkHttpResponse
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.scalars.ScalarsConverterFactory
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Headers
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln
import kotlin.math.max

interface HibpApiService {
    @Headers(
        "User-Agent: CyberSentinel/1.0 (+https://github.com/yourrepo)",
        "Add-Padding: true"
    )
    @GET("range/{prefix}")
    suspend fun range(@Path("prefix") prefix: String): Response<String>

    companion object {
        const val BASE_URL = "https://api.pwnedpasswords.com/"

        fun create(): HibpApiService {
            val retry429 = Interceptor { chain ->
                val req = chain.request()
                var resp = chain.proceed(req)
                var attempt = 0
                
                while ((resp.code == 429 || resp.code >= 500) && attempt < 3) {
                    // exponential backoff 300ms, 600ms, 1200ms
                    val waitMs = 300L shl attempt
                    Thread.sleep(waitMs)
                    attempt++
                    resp = chain.proceed(req)
                }
                
                resp
            }

            val client = OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .addInterceptor(retry429)
                .build()

            return Retrofit.Builder()
                .baseUrl(BASE_URL)
                .client(client)
                .addConverterFactory(ScalarsConverterFactory.create())
                .build()
                .create(HibpApiService::class.java)
        }
    }
}

sealed class HibpResult {
    data class Ok(
        val compromised: Boolean,
        val breachCount: Long,
        val strength: StrengthScore,
        val recommendations: List<String>
    ) : HibpResult()

    data class Error(val message: String) : HibpResult()
}

enum class StrengthLevel { VERY_WEAK, WEAK, MEDIUM, STRONG, VERY_STRONG }
data class StrengthScore(val level: StrengthLevel, val entropyBits: Double)

@Singleton
class HibpPasswordChecker @Inject constructor() {
    private val api: HibpApiService = HibpApiService.create()
    
    // Prefix cache s TTL pro optimalizaci
    private val ttlMs = 10 * 60 * 1000L
    private val prefixCache = object : LinkedHashMap<String, Pair<Long, String>>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<Long, String>>?) =
            size > 128
    }

    /** Hlavní metoda – přijímá CharArray kvůli bezpečnosti. */
    suspend fun checkPassword(password: CharArray): HibpResult = withContext(Dispatchers.IO) {
        if (password.isEmpty()) return@withContext HibpResult.Error("Heslo je prázdné")

        // 1) SHA-1 jako UPPERCASE HEX
        val sha1 = sha1Upper(password)

        // Prefix/suffix
        val prefix = sha1.take(5)
        val suffix = sha1.drop(5)

        try {
            // Cache lookup
            val now = System.currentTimeMillis()
            val cached = synchronized(prefixCache) {
                prefixCache[prefix]?.takeIf { (t, _) -> now - t < ttlMs }?.second
            }

            val body = if (cached != null) {
                cached
            } else {
                val resp = api.range(prefix)
                if (!resp.isSuccessful) {
                    return@withContext HibpResult.Error("HIBP odpověď: HTTP ${resp.code()}")
                }
                val b = resp.body().orEmpty()
                synchronized(prefixCache) { prefixCache[prefix] = now to b }
                b
            }

            // 2) Najdi suffix case-insensitive; zpracuj CR/LF robustně
            val breachCount: Long = body
                .lineSequence() // lazy
                .map { it.trim() }
                .filter { it.isNotEmpty() && it.contains(':') }
                .mapNotNull { line ->
                    val i = line.indexOf(':')
                    if (i <= 0) null
                    else {
                        val sfx = line.substring(0, i)
                        val cnt = line.substring(i + 1).trim().toLongOrNull()
                        if (sfx.equals(suffix, ignoreCase = true)) cnt else null
                    }
                }
                .firstOrNull() ?: 0L

            // 3) Vyhodnoť sílu hesla (lokálně, žádné odesílání)
            val strength = estimateStrength(password)

            // 4) Doporučení – kombinace kompromitace + síly
            val recs = buildRecommendations(breachCount, strength, password)

            HibpResult.Ok(
                compromised = breachCount > 0,
                breachCount = breachCount,
                strength = strength,
                recommendations = recs
            )
        } catch (t: Throwable) {
            HibpResult.Error("Chyba při ověřování: ${t.message ?: t::class.java.simpleName}")
        } finally {
            // Bezpečnost: vynulovat heslo v paměti
            password.fill('\u0000')
        }
    }

    // ---- Helpers ------------------------------------------------------------

    private fun sha1Upper(chars: CharArray): String {
        val md = MessageDigest.getInstance("SHA-1")
        // převeď bez mezipamětí stringů
        val bytes = ByteArray(chars.size)
        for (i in chars.indices) bytes[i] = chars[i].code.toByte()
        val digest = md.digest(bytes)
        // vynuluj dočasné pole
        bytes.fill(0)
        return buildString(digest.size * 2) {
            digest.forEach { append("%02X".format(it)) }
        }
    }

    /** Jednoduchý odhad entropie + penalizace vzorů (bez externích lib). */
    internal fun estimateStrength(pw: CharArray): StrengthScore {
        var hasLower = false; var hasUpper = false; var hasDigit = false; var hasSpecial = false
        var repeats = 0
        var prev: Char? = null
        var digitsRun = 0
        var commonPenalty = 0.0

        // detekce znaků bez tvorby Stringů
        for (i in pw.indices) {
            val c = pw[i]
            when {
                c.isLowerCase() -> hasLower = true
                c.isUpperCase() -> hasUpper = true
                c.isDigit()     -> { hasDigit = true; digitsRun++ }
                else            -> hasSpecial = true
            }
            if (prev != null && prev == c) repeats++ else repeats = 0
            prev = c
            if (!c.isDigit()) digitsRun = 0
        }

        // velikost abecedy (hrubý odhad)
        val alphabet = when {
            hasLower && hasUpper && hasDigit && hasSpecial -> 95.0
            arrayOf(hasLower, hasUpper, hasDigit).count { it } >= 2 -> 62.0
            hasDigit -> 10.0
            else -> 26.0
        }

        var entropy = pw.size * ln(alphabet) / ln(2.0)

        // Penalizace
        if (pw.size < 8) entropy -= 10.0
        if (repeats >= 2) entropy -= 8.0
        if (digitsRun >= 6) entropy -= 10.0

        // hrubá kontrola common frází
        val lower = CharArray(pw.size) { i -> pw[i].lowercaseChar() }
        val common = arrayOf("password", "123456", "qwerty", "letmein", "admin")
        common.forEach { word ->
            if (contains(lower, word)) commonPenalty += 20.0
        }
        lower.fill('\u0000')

        entropy = max(0.0, entropy - commonPenalty)

        val level = when {
            entropy < 28 -> StrengthLevel.VERY_WEAK     // < ~2^28
            entropy < 36 -> StrengthLevel.WEAK
            entropy < 60 -> StrengthLevel.MEDIUM
            entropy < 80 -> StrengthLevel.STRONG
            else -> StrengthLevel.VERY_STRONG
        }
        return StrengthScore(level, entropy)
    }

    private fun contains(hay: CharArray, needle: String): Boolean {
        outer@ for (i in 0..hay.size - needle.length) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    /** Veřejná metoda pro rychlý lokální odhad síly hesla (bez síťového volání) */
    fun quickEstimate(password: CharArray): StrengthScore {
        return estimateStrength(password)
    }

    private fun buildRecommendations(
        breachCount: Long,
        strength: StrengthScore,
        password: CharArray
    ): List<String> {
        val rec = mutableListOf<String>()

        when {
            breachCount > 100_000 -> {
                rec += "Heslo bylo kompromitováno $breachCount× – změňte ho IHNED."
                rec += "Aktivujte 2FA tam, kde to jde."
            }
            breachCount > 10_000 -> {
                rec += "Heslo je velmi časté v únicích ($breachCount×)."
                rec += "Změňte ho a nepoužívejte znovu."
            }
            breachCount > 0 -> {
                rec += "Heslo se v únicích vyskytuje ($breachCount×). Zvažte změnu."
            }
            else -> rec += "Heslo nebylo nalezeno v známých únicích."
        }

        if (password.size < 12) rec += "Cílte na délku 12+ znaků."
        val s = password.concatToString()
        val hasLower = s.any(Char::isLowerCase)
        val hasUpper = s.any(Char::isUpperCase)
        val hasDigit = s.any(Char::isDigit)
        val hasSpecial = s.any { !it.isLetterOrDigit() }
        if (listOf(hasLower, hasUpper, hasDigit, hasSpecial).count { it } < 3) {
            rec += "Kombinujte velká/malá písmena, čísla a speciální znaky."
        }

        if (breachCount == 0L && strength.level >= StrengthLevel.STRONG) {
            rec += "Silné heslo – dobrá práce!"
        }
        return rec
    }
}