package com.cybersentinel.app.data.remote.kev

import retrofit2.http.GET

data class KevFeed(val vulnerabilities: List<KevItem>)
data class KevItem(val cveID: String, val dateAdded: String?)

interface KevApi {
    // CISA KEV JSON (endpoint is stable; server may redirect — OkHttp follows)
    @GET("known_exploited_vulnerabilities.json")
    suspend fun feed(): KevFeed
}