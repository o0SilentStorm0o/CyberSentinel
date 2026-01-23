package com.cybersentinel.app.data.local


import androidx.room.Entity
import androidx.room.PrimaryKey


@Entity(tableName = "favorites")
data class FavoriteEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val label: String,
    val value: String,
    val createdAt: Long = System.currentTimeMillis()
)