package com.cybersentinel.app.data.local

import androidx.room.*

@Entity(tableName = "cve")
data class CveEntity(
    @PrimaryKey val id: String,
    val summary: String,
    val publishedEpochSec: Long?,     // null if unknown
    val source: String,               // "NVD" | "CIRCL"
    val score: Int,                   // relevance score you compute
    val tagsCsv: String,              // "OS,Browser,KEV"
    val seen: Boolean = false,
    val acknowledged: Boolean = false,
    val insertedAtEpochMs: Long = System.currentTimeMillis(),
)

@Entity(tableName = "kev")
data class KevEntity(
    @PrimaryKey val cveId: String,
    val dateAddedEpochSec: Long?
)