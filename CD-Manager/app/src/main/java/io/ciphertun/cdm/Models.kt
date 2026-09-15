package io.ciphertun.cdm

data class FileReport(
    val name: String,
    val size: Long,
    val extension: String,
    val mime: String,
    val format: String,
    val application: String = "Unknown application",
    val protocols: List<String> = emptyList(),
    val confidence: Int,
    val encrypted: Boolean,
    val sha256: String,
    val fields: List<Pair<String, String>> = emptyList(),
    val notes: List<String> = emptyList(),
    val rawText: String? = null,
    val stringsPreview: List<String> = emptyList(),
    val hexPreview: String = "",
    val adapterStatus: String = "Generic analysis",
    val warnings: List<String> = emptyList()
)

data class FormatSpec(
    val extension: String,
    val name: String,
    val family: String,
    val status: String
)

data class CryptoJobResult(
    val outputUri: android.net.Uri,
    val bytes: Long
)
