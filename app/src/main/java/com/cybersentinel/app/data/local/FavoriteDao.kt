package com.cybersentinel.app.data.local


import androidx.room.*
import kotlinx.coroutines.flow.Flow


@Dao
interface FavoriteDao {
    @Query("SELECT * FROM favorites ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<FavoriteEntity>>


    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(e: FavoriteEntity)


    @Delete
    suspend fun delete(e: FavoriteEntity)
}