package com.cybersentinel.app.data.local

import androidx.room.*

/**
 * Room entity for persisting security events.
 * Events are the primary unit of persistence — signals are transient,
 * incidents are reconstructed from events by RootCauseResolver.
 */
@Entity(
    tableName = "security_events",
    indices = [
        Index(value = ["packageName"]),
        Index(value = ["source"]),
        Index(value = ["startTime"]),
        Index(value = ["severity"])
    ]
)
data class SecurityEventEntity(
    @PrimaryKey
    val id: String,
    val startTime: Long,
    val endTime: Long?,
    val source: String,       // SignalSource.name
    val eventType: String,    // EventType.name
    val severity: String,     // SignalSeverity.name
    val packageName: String?,
    val summary: String,
    /** JSON-encoded signal IDs */
    val signalIds: String? = null,
    /** JSON-encoded metadata map */
    val metadata: String? = null,
    val isPromoted: Boolean = false,
    /** Auto-expire old events */
    val expiresAt: Long? = null
)

@Dao
interface SecurityEventDao {
    @Query("SELECT * FROM security_events ORDER BY startTime DESC")
    suspend fun getAll(): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE packageName = :packageName ORDER BY startTime DESC")
    suspend fun getByPackage(packageName: String): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE source = :source ORDER BY startTime DESC")
    suspend fun getBySource(source: String): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE severity IN ('CRITICAL', 'HIGH') AND isPromoted = 0 ORDER BY startTime DESC")
    suspend fun getUnpromotedHighSeverity(): List<SecurityEventEntity>

    @Query("""
        SELECT * FROM security_events 
        WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM') 
           OR startTime >= :recentCutoff
        ORDER BY 
            CASE severity 
                WHEN 'CRITICAL' THEN 5 
                WHEN 'HIGH' THEN 4 
                WHEN 'MEDIUM' THEN 3 
                WHEN 'LOW' THEN 2 
                ELSE 1 
            END DESC, 
            startTime DESC
    """)
    suspend fun getActiveEvents(recentCutoff: Long): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE startTime >= :since ORDER BY startTime DESC")
    suspend fun getSince(since: Long): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE startTime >= :since AND packageName = :packageName ORDER BY startTime DESC")
    suspend fun getSinceForPackage(since: Long, packageName: String): List<SecurityEventEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(event: SecurityEventEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(events: List<SecurityEventEntity>)

    @Query("UPDATE security_events SET isPromoted = 1 WHERE id = :eventId")
    suspend fun markPromoted(eventId: String)

    @Query("DELETE FROM security_events WHERE expiresAt IS NOT NULL AND expiresAt < :now")
    suspend fun deleteExpired(now: Long = System.currentTimeMillis())

    @Query("DELETE FROM security_events WHERE startTime < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("SELECT COUNT(*) FROM security_events WHERE packageName = :packageName AND eventType = :eventType AND startTime >= :since")
    suspend fun countEventsSince(packageName: String, eventType: String, since: Long): Int

    @Query("DELETE FROM security_events")
    suspend fun deleteAll()
}
