package com.cybersentinel.app.di


import com.cybersentinel.app.data.remote.CveApi
import com.squareup.moshi.Moshi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import javax.inject.Singleton


@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {
    @Provides @Singleton
    fun okHttp(): OkHttpClient = OkHttpClient.Builder()
        .addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BASIC })
        .build()


    @Provides @Singleton
    fun moshi(): Moshi = Moshi.Builder()
        .add(com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory())
        .build()


    @Provides @Singleton
    fun retrofit(client: OkHttpClient, moshi: Moshi): Retrofit = Retrofit.Builder()
        .baseUrl("https://cve.circl.lu/")
        .client(client)
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()


    @Provides @Singleton
    fun cveApi(retrofit: Retrofit): CveApi = retrofit.create(CveApi::class.java)

    @Provides @Singleton
    fun nvdApi(moshi: Moshi, client: OkHttpClient): com.cybersentinel.app.data.remote.nvd.NvdApi =
        Retrofit.Builder()
            .baseUrl("https://services.nvd.nist.gov/")
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .client(client)
            .build()
            .create(com.cybersentinel.app.data.remote.nvd.NvdApi::class.java)

    @Provides @Singleton
    fun kevApi(okHttp: OkHttpClient, moshi: Moshi): com.cybersentinel.app.data.remote.kev.KevApi =
        Retrofit.Builder()
            .baseUrl("https://www.cisa.gov/sites/default/files/feeds/") // KEV JSON
            .client(okHttp.newBuilder().build())
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(com.cybersentinel.app.data.remote.kev.KevApi::class.java)
}