package com.cybersentinel.app.di


import android.content.Context
import androidx.room.Room
import com.cybersentinel.app.data.local.AppDatabase
import com.cybersentinel.app.data.local.FavoriteDao
import com.cybersentinel.app.data.local.CveDao
import com.cybersentinel.app.data.local.KevDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton


@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    @Provides @Singleton
    fun db(@ApplicationContext ctx: Context): AppDatabase =
        Room.databaseBuilder(ctx, AppDatabase::class.java, "cybersentinel.db")
            .fallbackToDestructiveMigration() // for v1->v2 migration
            .build()


    @Provides @Singleton
    fun favorites(db: AppDatabase): FavoriteDao = db.favorites()
    
    @Provides 
    fun cveDao(db: AppDatabase): CveDao = db.cveDao()
    
    @Provides 
    fun kevDao(db: AppDatabase): KevDao = db.kevDao()
}