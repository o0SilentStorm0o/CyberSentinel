package com.cybersentinel.app.data.remote


import retrofit2.http.GET
import retrofit2.http.Path


// Using cve.circl.lu public API as a simple source for demo
interface CveApi {
    @GET("api/last")
    suspend fun last(): List<CirclEntryDto>


    @GET("/api/cve/{id}")
    suspend fun byId(@Path("id") id: String): CirclEntryDto
}