package com.cybersentinel.app.data.local

import androidx.room.*

@Dao
interface CveDao {
    @Upsert
    suspend fun upsertAll(items: List<CveEntity>)

    @Query("SELECT * FROM cve WHERE acknowledged = 0 AND score >= :minScore ORDER BY publishedEpochSec DESC, insertedAtEpochMs DESC LIMIT :limit")
    suspend fun topRelevant(minScore: Int, limit: Int): List<CveEntity>

    @Query("UPDATE cve SET acknowledged = 1 WHERE id = :id")
    suspend fun markAcknowledged(id: String)

    @Query("SELECT EXISTS(SELECT 1 FROM cve WHERE id = :id AND acknowledged = 1)")
    suspend fun isAcknowledged(id: String): Boolean
}