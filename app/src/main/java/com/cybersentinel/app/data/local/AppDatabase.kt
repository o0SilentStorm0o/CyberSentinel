package com.cybersentinel.app.data.local


import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase


@Database(
    entities = [
        CveEntity::class, KevEntity::class, FavoriteEntity::class, 
        AppBaselineEntity::class, SecurityEventEntity::class, ConfigBaselineEntity::class
    ], 
    version = 5,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun favorites(): FavoriteDao
    abstract fun cveDao(): CveDao
    abstract fun kevDao(): KevDao
    abstract fun appBaselineDao(): AppBaselineDao
    abstract fun securityEventDao(): SecurityEventDao
    abstract fun configBaselineDao(): ConfigBaselineDao
    
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
        
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Add permission baseline columns
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `permissionSetHash` TEXT")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `highRiskPermissions` TEXT")
                // Add exported surface baseline columns
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `exportedActivityCount` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `exportedServiceCount` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `exportedReceiverCount` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `exportedProviderCount` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `unprotectedExportedCount` INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // ── Time correlation columns on app_baseline ──
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `lastUpdateAt` INTEGER")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `lastInstallerChangeAt` INTEGER")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `lastHighRiskPermAddedAt` INTEGER")
                db.execSQL("ALTER TABLE `app_baseline` ADD COLUMN `lastSpecialAccessEnabledAt` INTEGER")

                // ── Security events table ──
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS `security_events` (
                        `id` TEXT NOT NULL,
                        `startTime` INTEGER NOT NULL,
                        `endTime` INTEGER,
                        `source` TEXT NOT NULL,
                        `eventType` TEXT NOT NULL,
                        `severity` TEXT NOT NULL,
                        `packageName` TEXT,
                        `summary` TEXT NOT NULL,
                        `signalIds` TEXT,
                        `metadata` TEXT,
                        `isPromoted` INTEGER NOT NULL DEFAULT 0,
                        `expiresAt` INTEGER,
                        PRIMARY KEY(`id`)
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_packageName` ON `security_events` (`packageName`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_source` ON `security_events` (`source`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_startTime` ON `security_events` (`startTime`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_severity` ON `security_events` (`severity`)")

                // ── Config baseline table ──
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS `config_baseline` (
                        `id` INTEGER NOT NULL,
                        `timestamp` INTEGER NOT NULL,
                        `userCaCertFingerprints` TEXT,
                        `userCaCertCount` INTEGER NOT NULL DEFAULT 0,
                        `privateDnsMode` TEXT,
                        `privateDnsHostname` TEXT,
                        `vpnActive` INTEGER NOT NULL DEFAULT 0,
                        `globalProxyConfigured` INTEGER NOT NULL DEFAULT 0,
                        `proxyHost` TEXT,
                        `enabledAccessibilityServices` TEXT,
                        `enabledNotificationListeners` TEXT,
                        `defaultSmsApp` TEXT,
                        `defaultDialerApp` TEXT,
                        `developerOptionsEnabled` INTEGER NOT NULL DEFAULT 0,
                        `usbDebuggingEnabled` INTEGER NOT NULL DEFAULT 0,
                        `installFromUnknownSourcesEnabled` INTEGER NOT NULL DEFAULT 0,
                        `configHash` TEXT,
                        PRIMARY KEY(`id`)
                    )
                """.trimIndent())
            }
        }
    }
}