package com.cybersentinel.app.data.local

import androidx.room.*

@Dao
interface KevDao {
    @Upsert
    suspend fun upsertAll(ids: List<KevEntity>)

    @Query("SELECT EXISTS(SELECT 1 FROM kev WHERE cveId = :id)")
    suspend fun exists(id: String): Boolean

    @Query("DELETE FROM kev")
    suspend fun clear()
}