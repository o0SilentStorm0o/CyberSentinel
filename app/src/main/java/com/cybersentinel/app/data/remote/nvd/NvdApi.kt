package com.cybersentinel.app.data.remote.nvd

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.Query

interface NvdApi {
    @GET("rest/json/cves/2.0")
    @Headers("User-Agent: CyberSentinel/1.0 (Android)")
    suspend fun search(
        @Query("pubStartDate") start: String,
        @Query("pubEndDate") end: String,
        @Query("startIndex") startIndex: Int = 0,
        @Query("resultsPerPage") rpp: Int = 50,
        @Query("virtualMatchString") vms: String,
        @Query("apiKey") apiKey: String? = null
    ): NvdResponse
}

@JsonClass(generateAdapter = true)
data class NvdResponse(
    @Json(name = "vulnerabilities") val vulnerabilities: List<NvdVuln> = emptyList()
)

@JsonClass(generateAdapter = true)
data class NvdVuln(
    @Json(name = "cve") val cve: NvdCve
)

@JsonClass(generateAdapter = true)
data class NvdCve(
    @Json(name = "id") val id: String,
    @Json(name = "published") val published: String?,
    @Json(name = "descriptions") val descriptions: List<NvdDescription> = emptyList(),
    @Json(name = "references") val references: List<NvdReference> = emptyList(),
    @Json(name = "metrics") val metrics: NvdMetrics? = null
)

@JsonClass(generateAdapter = true)
data class NvdDescription(
    @Json(name = "lang") val lang: String?,
    @Json(name = "value") val value: String?
)

@JsonClass(generateAdapter = true)
data class NvdReference(
    @Json(name = "url") val url: String?
)

@JsonClass(generateAdapter = true)
data class NvdMetrics(
    @Json(name = "cvssMetricV31") val v31: List<NvdCvssMetric>? = null,
    @Json(name = "cvssMetricV30") val v30: List<NvdCvssMetric>? = null,
    @Json(name = "cvssMetricV2")  val v2:  List<NvdCvssMetric>? = null
)

@JsonClass(generateAdapter = true)
data class NvdCvssMetric(
    @Json(name = "cvssData") val data: NvdCvssData?
)

@JsonClass(generateAdapter = true)
data class NvdCvssData(
    @Json(name = "baseScore") val baseScore: Double?
)