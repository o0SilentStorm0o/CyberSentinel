package com.cybersentinel.app.data.repo

import com.cybersentinel.app.data.remote.CveApi
import com.cybersentinel.app.data.remote.nvd.NvdApi
import com.cybersentinel.app.data.remote.nvd.NvdResponse
import com.cybersentinel.app.data.remote.toDomain
import com.cybersentinel.app.data.local.CveDao
import com.cybersentinel.app.data.local.CveEntity
import com.cybersentinel.app.data.kev.KevCatalog
import com.cybersentinel.app.domain.device.DeviceProfile
import com.cybersentinel.app.domain.device.DeviceProfileProvider
import com.cybersentinel.app.domain.model.CveItem
import com.cybersentinel.app.domain.scoring.RelevantCve
import java.time.ZonedDateTime
import java.time.ZoneOffset
import java.time.Duration
import java.time.format.DateTimeFormatter
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CveRepository @Inject constructor(
    private val nvdApi: NvdApi,
    private val circlApi: CveApi,
    private val cveDao: CveDao,
    private val kevCatalog: KevCatalog,
    private val profileProvider: DeviceProfileProvider
) {

    private fun nvdToDomain(response: NvdResponse): List<CveItem> =
        response.vulnerabilities.map { v ->
            val cve = v.cve
            val desc = cve.descriptions.firstOrNull { it.lang.equals("en", true) }?.value
                ?: cve.descriptions.firstOrNull()?.value ?: "—"
            
            CveItem(
                id = cve.id,
                summary = desc,
                cvss = cve.metrics?.v31?.firstOrNull()?.data?.baseScore
                    ?: cve.metrics?.v30?.firstOrNull()?.data?.baseScore
                    ?: cve.metrics?.v2?.firstOrNull()?.data?.baseScore
            )
        }

    /**
     * Server-side stránkování a datumové filtrování přes NVD.
     * daysBack: jak daleko do historie (např. 365) - automaticky omezeno na 119 dní
     * page: 0-based
     * pageSize: např. 50
     * Používá virtualMatchString pro Android a Chrome.
     */
    suspend fun searchNvdForDevice(
        daysBack: Int,
        page: Int,
        pageSize: Int,
        profile: DeviceProfile
    ): List<CveItem> {
        val end = ZonedDateTime.now(ZoneOffset.UTC)
        val wantedStart = end.minusDays(daysBack.toLong())

        val start = if (Duration.between(wantedStart, end).toDays() > 119) {
            end.minusDays(119)
        } else {
            wantedStart
        }

        val fmt = DateTimeFormatter.ISO_INSTANT
        val pubStart = fmt.format(start)
        val pubEnd = fmt.format(end)

        val vmsTargets = buildList {
            add("cpe:2.3:o:google:android:*")
            add("cpe:2.3:a:google:chrome:*")
            add("cpe:2.3:a:google:android_webview:*")
        }

        val startIndex = page * pageSize
        val results = mutableListOf<CveItem>()

        for (vms in vmsTargets) {
            try {
                val resp = nvdApi.search(
                    start = pubStart,
                    end = pubEnd,
                    startIndex = startIndex,
                    rpp = pageSize,
                    vms = vms,
                    apiKey = null
                )
                results += nvdToDomain(resp)
            } catch (e: Exception) {
                continue
            }
        }

        return results.distinctBy { it.id }
    }

    suspend fun loadLatest(): List<CveItem> {
        return circlApi.last()
            .asSequence()
            .map { it.toDomain() }
            .filter { it.id != "—" && it.summary != "—" }
            .take(50)
            .toList()
    }

    // Cache + offline support methods
    suspend fun saveToCache(items: List<RelevantCve>, source: String) {
        val rows = items.map {
            CveEntity(
                id = it.item.id,
                summary = it.item.summary,
                publishedEpochSec = null, // We'll add published date parsing later
                source = source,
                score = it.score,
                tagsCsv = it.tags.joinToString(","),
            )
        }
        cveDao.upsertAll(rows)
    }

    suspend fun topCachedRelevant(minScore: Int, limit: Int): List<CveEntity> =
        cveDao.topRelevant(minScore, limit)

    suspend fun acknowledge(id: String) = cveDao.markAcknowledged(id)
    suspend fun isAcknowledged(id: String) = cveDao.isAcknowledged(id)
    
    fun getDeviceProfile(): DeviceProfile = profileProvider.get()
}