package com.cybersentinel.app.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

@Dao
interface AppBaselineDao {
    
    @Query("SELECT * FROM app_baseline WHERE packageName = :packageName")
    suspend fun getBaseline(packageName: String): AppBaselineEntity?
    
    @Query("SELECT * FROM app_baseline")
    suspend fun getAllBaselines(): List<AppBaselineEntity>
    
    @Query("SELECT * FROM app_baseline WHERE isSystemApp = 1")
    suspend fun getSystemAppBaselines(): List<AppBaselineEntity>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBaseline(baseline: AppBaselineEntity)
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBaselines(baselines: List<AppBaselineEntity>)
    
    @Query("DELETE FROM app_baseline WHERE packageName = :packageName")
    suspend fun deleteBaseline(packageName: String)
    
    /** Find baselines that no longer have a corresponding installed app */
    @Query("SELECT * FROM app_baseline WHERE packageName NOT IN (:currentPackages)")
    suspend fun findRemovedApps(currentPackages: List<String>): List<AppBaselineEntity>
    
    @Query("SELECT COUNT(*) FROM app_baseline")
    suspend fun getBaselineCount(): Int

    @Query("SELECT COUNT(*) FROM app_baseline WHERE isSystemApp = 1")
    suspend fun getSystemAppBaselineCount(): Int
}
