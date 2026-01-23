package com.cybersentinel.app.data.remote


import com.cybersentinel.app.domain.model.CveItem
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass


@JsonClass(generateAdapter = true)
data class CirclEntryDto(
    // klasické CVE varianty:
    @Json(name = "id") val id: String? = null,
    @Json(name = "cve") val cve: String? = null,
    @Json(name = "summary") val summary: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "published") val published: String? = null,

    // CSAF advisory varianta:
    @Json(name = "document") val document: CsafDocumentDto? = null
)

@JsonClass(generateAdapter = true)
data class CsafDocumentDto(
    @Json(name = "title") val title: String? = null,
    @Json(name = "tracking") val tracking: CsafTrackingDto? = null,
    @Json(name = "notes") val notes: List<CsafNoteDto>? = null
)

@JsonClass(generateAdapter = true)
data class CsafTrackingDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "initial_release_date") val initialReleaseDate: String? = null
)

@JsonClass(generateAdapter = true)
data class CsafNoteDto(
    @Json(name = "category") val category: String? = null,
    @Json(name = "text") val text: String? = null
)


fun CirclEntryDto.toDomain(): CveItem {
    // 1) ID zkus v pořadí: CVE -> CSAF tracking.id
    val bestId = id ?: cve ?: document?.tracking?.id ?: "—"

    // 2) Teaser/summary: CVE summary/description -> CSAF notes[summary] -> CSAF title
    val csafSummaryText = document?.notes
        ?.firstOrNull { it.category.equals("summary", ignoreCase = true) }
        ?.text

    val bestSummary = summary
        ?: description
        ?: csafSummaryText
        ?: document?.title
        ?: "—"

    return CveItem(
        id = bestId,
        summary = bestSummary,
        cvss = null
    )
}