package io.ciphertun.cdm.backend.kotlin

object KotlinCore {
    const val NAME = "Kotlin Core Backend"
    fun available() = true
    fun boundedSample(data: ByteArray, maxBytes: Int = 1024 * 1024): ByteArray =
        if (data.size <= maxBytes) data else data.copyOf(maxBytes)
    fun printableRatio(data: ByteArray): Double = if (data.isEmpty()) 0.0 else
        data.count { it.toInt() in 0x20..0x7e || it == 10.toByte() || it == 13.toByte() || it == 9.toByte() }.toDouble() / data.size
}
