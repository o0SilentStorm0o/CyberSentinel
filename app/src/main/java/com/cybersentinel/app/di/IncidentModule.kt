package com.cybersentinel.app.di

import com.cybersentinel.app.domain.llm.ModelDownloader
import com.cybersentinel.app.domain.security.DefaultRootCauseResolver
import com.cybersentinel.app.domain.security.RootCauseResolver
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import java.io.File
import javax.inject.Singleton

/**
 * Hilt module for incident/security domain bindings.
 *
 * Provides:
 *  - [RootCauseResolver] → [DefaultRootCauseResolver] (no-arg ctor, singleton)
 *  - [ModelDownloader] → stub implementation (will be replaced when actual download is wired)
 *
 * Sprint UI-1: DI wiring for incident ViewModels.
 */
@Module
@InstallIn(SingletonComponent::class)
object IncidentModule {

    @Provides
    @Singleton
    fun provideRootCauseResolver(): RootCauseResolver = DefaultRootCauseResolver()

    /**
     * Stub ModelDownloader — always returns false (no-op).
     * Will be replaced by a real HTTP downloader when model download is implemented.
     */
    @Provides
    @Singleton
    fun provideModelDownloader(): ModelDownloader = object : ModelDownloader {
        override fun download(
            url: String,
            target: File,
            onProgress: ((downloaded: Long, total: Long) -> Unit)?
        ): Boolean = false
    }
}
