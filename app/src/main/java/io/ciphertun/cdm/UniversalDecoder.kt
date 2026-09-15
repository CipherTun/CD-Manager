package io.ciphertun.cdm

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import java.util.zip.InflaterInputStream

/**
 * Format-agnostic reversible decoding layer.
 * It never labels an output as decrypted unless a format-specific adapter proves it.
 */
object UniversalDecoder {
    data class Result(
        val name: String,
        val bytes: ByteArray,
        val description: String,
        val confidence: Int
    )

    fun run(input: ByteArray): List<Result> {
        if (input.isEmpty()) return emptyList()
        val tasks = listOf<Callable<Result?>>(
            Callable { decodeBase64(input) },
            Callable { decodeHex(input) },
            Callable { decodeGzip(input) },
            Callable { decodeZlib(input) },
            Callable { decodeUrlBase64(input) }
        )
        val pool = Executors.newFixedThreadPool(tasks.size)
        return try {
            pool.invokeAll(tasks, 4, TimeUnit.SECONDS)
                .mapNotNull { runCatching { it.get() }.getOrNull() }
                .filter { it.bytes.isNotEmpty() && !it.bytes.contentEquals(input) }
                .distinctBy { "${it.name}:${it.bytes.contentHashCode()}" }
                .sortedByDescending { it.confidence }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun decodeBase64(input: ByteArray): Result? {
        val text = input.toString(Charsets.US_ASCII).trim()
        if (text.length < 8 || text.length % 4 != 0 || !text.matches(Regex("[A-Za-z0-9+/=\\r\\n]+"))) return null
        val out = runCatching { Base64.decode(text, Base64.DEFAULT) }.getOrNull() ?: return null
        return if (out.size >= 4) Result("Base64", out, "Standard Base64 decoded", 92) else null
    }

    private fun decodeUrlBase64(input: ByteArray): Result? {
        val text = input.toString(Charsets.US_ASCII).trim()
        if (text.length < 8 || !text.matches(Regex("[A-Za-z0-9_-]+=*"))) return null
        val padded = text + "=".repeat((4 - text.length % 4) % 4)
        val out = runCatching { Base64.decode(padded.replace('-', '+').replace('_', '/'), Base64.DEFAULT) }.getOrNull() ?: return null
        return if (out.size >= 4) Result("Base64URL", out, "URL-safe Base64 decoded", 90) else null
    }

    private fun decodeHex(input: ByteArray): Result? {
        val text = input.toString(Charsets.US_ASCII).trim().replace(Regex("\\s+"), "")
        if (text.length < 8 || text.length % 2 != 0 || !text.matches(Regex("[0-9A-Fa-f]+"))) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) out[i] = text.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return Result("Hex", out, "Hexadecimal bytes decoded", 88)
    }

    private fun decodeGzip(input: ByteArray): Result? {
        if (input.size < 2 || input[0] != 0x1f.toByte() || input[1] != 0x8b.toByte()) return null
        return decompress("GZIP", input) { GZIPInputStream(it) }
    }

    private fun decodeZlib(input: ByteArray): Result? {
        if (input.size < 2) return null
        val cmf = input[0].toInt() and 255
        val flg = input[1].toInt() and 255
        if ((cmf and 0x0f) != 8 || ((cmf shl 8) + flg) % 31 != 0) return null
        return decompress("ZLIB", input) { InflaterInputStream(it) }
    }

    private fun decompress(name: String, input: ByteArray, factory: (ByteArrayInputStream) -> java.io.InputStream): Result? = runCatching {
        val out = ByteArrayOutputStream()
        factory(ByteArrayInputStream(input)).use { ins ->
            val buf = ByteArray(64 * 1024)
            var total = 0
            while (true) {
                val n = ins.read(buf)
                if (n <= 0) break
                total += n
                if (total > 8 * 1024 * 1024) return null
                out.write(buf, 0, n)
            }
        }
        val bytes = out.toByteArray()
        if (bytes.isEmpty()) null else Result(name, bytes, "$name decompressed", 98)
    }.getOrNull()
}
