package com.cybersentinel.app.data.kev

import com.cybersentinel.app.data.local.KevDao
import com.cybersentinel.app.data.local.KevEntity
import com.cybersentinel.app.data.remote.kev.KevApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.ZonedDateTime
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KevCatalog @Inject constructor(
    private val api: KevApi,
    private val kevDao: KevDao,
) {
    private var lastRefreshEpochMs = 0L

    suspend fun refreshIfStale() = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        if (now - lastRefreshEpochMs < 24 * 60 * 60 * 1000L) return@withContext
        
        try {
            val feed = api.feed()
            val rows = feed.vulnerabilities.map {
                KevEntity(
                    cveId = it.cveID.trim(),
                    dateAddedEpochSec = it.dateAdded?.let { d ->
                        runCatching { ZonedDateTime.parse(d).toEpochSecond() }.getOrNull()
                    }
                )
            }
            kevDao.clear()
            kevDao.upsertAll(rows)
            lastRefreshEpochMs = now
        } catch (e: Exception) {
            // Log error but continue with stale cache
        }
    }

    suspend fun isKev(id: String): Boolean = kevDao.exists(id)
}