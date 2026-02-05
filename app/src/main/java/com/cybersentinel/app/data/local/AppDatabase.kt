package com.cybersentinel.app.data.local


import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase


@Database(
    entities = [CveEntity::class, KevEntity::class, FavoriteEntity::class, AppBaselineEntity::class], 
    version = 3,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun favorites(): FavoriteDao
    abstract fun cveDao(): CveDao
    abstract fun kevDao(): KevDao
    abstract fun appBaselineDao(): AppBaselineDao
    
    companion object {
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS `app_baseline` (
                        `packageName` TEXT NOT NULL,
                        `certSha256` TEXT NOT NULL,
                        `versionCode` INTEGER NOT NULL,
                        `versionName` TEXT,
                        `isSystemApp` INTEGER NOT NULL,
                        `installerPackage` TEXT,
                        `apkPath` TEXT,
                        `firstSeenAt` INTEGER NOT NULL,
                        `lastSeenAt` INTEGER NOT NULL,
                        `lastCertChangeAt` INTEGER NOT NULL DEFAULT 0,
                        `previousCertSha256` TEXT,
                        `scanCount` INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY(`packageName`)
                    )
                """.trimIndent())
            }
        }
    }
}