package com.cybersentinel.app.data.local


import androidx.room.Database
import androidx.room.RoomDatabase


@Database(
    entities = [CveEntity::class, KevEntity::class, FavoriteEntity::class], 
    version = 2,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun favorites(): FavoriteDao
    abstract fun cveDao(): CveDao
    abstract fun kevDao(): KevDao
}