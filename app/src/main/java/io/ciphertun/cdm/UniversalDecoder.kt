package io.ciphertun.cdm

import android.util.Base64
import org.apache.commons.compress.archivers.ArchiveStreamFactory
import org.apache.commons.compress.compressors.CompressorInputStream
import org.apache.commons.compress.compressors.CompressorStreamFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import java.util.zip.InflaterInputStream

/**
 * Content-first universal decoding/extraction layer.
 *
 * This file intentionally does NOT call generic decoding "decryption".
 * Proprietary/encrypted formats must still be handled by their verified
 * format-specific adapter when the required key/password/material exists.
 */
object UniversalDecoder {
    data class Result(
        val name: String,
        val bytes: ByteArray,
        val description: String,
        val confidence: Int,
        val detectedFormat: String? = null,
        val mime: String? = null,
        val children: List<Result> = emptyList()
    )

    private const val MAX_OUTPUT = 8 * 1024 * 1024
    private const val MAX_CHILDREN = 100
    private const val MAX_CHILD = 512 * 1024
    private const val MAX_DEPTH = 3

    fun run(input: ByteArray): List<Result> = runInternal(input, 0)

    private fun runInternal(input: ByteArray, depth: Int): List<Result> {
        if (input.isEmpty()) return emptyList()

        val tasks = listOf<Callable<Result?>>(
            Callable { decodeBase64(input) },
            Callable { decodeBase64Url(input) },
            Callable { decodeHex(input) },
            Callable { decodePercent(input) },
            Callable { decodeJwtPayload(input) },
            Callable { decodeGzip(input) },
            Callable { decodeZlib(input) },
            Callable { decodeCommonsCompression(input) }
        )

        val pool = Executors.newFixedThreadPool(tasks.size)

        return try {
            val direct = pool.invokeAll(tasks, 5, TimeUnit.SECONDS)
                .mapNotNull { runCatching { it.get() }.getOrNull() }
                .filter { it.bytes.isNotEmpty() && !it.bytes.contentEquals(input) }
                .filter { plausible(it.bytes) }
                .map { enrich(it, depth) }
                .distinctBy { "${it.name}:${it.bytes.contentHashCode()}" }
                .sortedByDescending { it.confidence }

            val archive = inspectArchive(input, depth)

            (direct + archive)
                .distinctBy { "${it.name}:${it.bytes.contentHashCode()}" }
                .sortedByDescending { it.confidence }
                .take(16)
        } finally {
            pool.shutdownNow()
        }
    }

    private fun enrich(result: Result, depth: Int): Result {
        val sig = signature(result.bytes)

        return result.copy(
            detectedFormat = sig?.first,
            mime = sig?.second,
            children = if (depth < MAX_DEPTH && sig == null) {
                runInternal(result.bytes, depth + 1)
            } else {
                emptyList()
            }
        )
    }

    private fun decodeBase64(input: ByteArray): Result? {
        val text = input.toString(StandardCharsets.US_ASCII).trim()

        if (
            text.length < 8 ||
            text.length % 4 != 0 ||
            text.length > MAX_OUTPUT * 2 ||
            !text.matches(Regex("[A-Za-z0-9+/=\\r\\n]+"))
        ) return null

        val out = runCatching {
            Base64.decode(text, Base64.DEFAULT)
        }.getOrNull() ?: return null

        return if (out.size >= 4) {
            Result(
                "Base64",
                out,
                "Standard Base64 decoded",
                92
            )
        } else {
            null
        }
    }

    private fun decodeBase64Url(input: ByteArray): Result? {
        val text = input.toString(StandardCharsets.US_ASCII).trim()

        if (
            text.length < 8 ||
            text.length > MAX_OUTPUT * 2 ||
            !text.matches(Regex("[A-Za-z0-9_-]+=*"))
        ) return null

        val padded = text + "=".repeat((4 - text.length % 4) % 4)

        val out = runCatching {
            Base64.decode(
                padded.replace('-', '+').replace('_', '/'),
                Base64.DEFAULT
            )
        }.getOrNull() ?: return null

        return if (out.size >= 4) {
            Result(
                "Base64URL",
                out,
                "URL-safe Base64 decoded",
                90
            )
        } else {
            null
        }
    }

    private fun decodeHex(input: ByteArray): Result? {
        val text = input.toString(StandardCharsets.US_ASCII)
            .trim()
            .replace(Regex("\\s+"), "")

        if (
            text.length < 8 ||
            text.length % 2 != 0 ||
            !text.matches(Regex("[0-9A-Fa-f]+"))
        ) return null

        val out = ByteArray(text.length / 2)

        for (i in out.indices) {
            out[i] = text
                .substring(i * 2, i * 2 + 2)
                .toInt(16)
                .toByte()
        }

        return if (out.size >= 4) {
            Result(
                "Hex",
                out,
                "Hexadecimal bytes decoded",
                88
            )
        } else {
            null
        }
    }

    private fun decodePercent(input: ByteArray): Result? {
        val text = input.toString(StandardCharsets.UTF_8).trim()

        if (
            !text.contains('%') ||
            !Regex("%(?:[0-9A-Fa-f]{2})").containsMatchIn(text)
        ) return null

        val out = ByteArrayOutputStream()
        var i = 0

        while (i < text.length) {
            if (
                text[i] == '%' &&
                i + 2 < text.length &&
                text.substring(i + 1, i + 3)
                    .matches(Regex("[0-9A-Fa-f]{2}"))
            ) {
                out.write(text.substring(i + 1, i + 3).toInt(16))
                i += 3
            } else {
                out.write(text[i].code)
                i++
            }
        }

        return Result(
            "Percent encoding",
            out.toByteArray(),
            "Percent-encoded bytes decoded",
            84
        )
    }

    private fun decodeJwtPayload(input: ByteArray): Result? {
        val parts = input
            .toString(StandardCharsets.UTF_8)
            .trim()
            .split('.')

        if (parts.size != 3 || parts[1].length < 4) return null

        val padded = parts[1] + "=".repeat((4 - parts[1].length % 4) % 4)

        val out = runCatching {
            Base64.decode(
                padded.replace('-', '+').replace('_', '/'),
                Base64.DEFAULT
            )
        }.getOrNull() ?: return null

        return if (out.isNotEmpty()) {
            Result(
                "JWT payload",
                out,
                "JWT payload decoded; signature not verified",
                95
            )
        } else {
            null
        }
    }

    private fun decodeGzip(input: ByteArray): Result? {
        if (
            input.size < 3 ||
            input[0] != 0x1f.toByte() ||
            input[1] != 0x8b.toByte() ||
            input[2] != 0x08.toByte()
        ) return null

        return decompress("GZIP", input) {
            GZIPInputStream(it)
        }
    }

    private fun decodeZlib(input: ByteArray): Result? {
        if (input.size < 2) return null

        val cmf = input[0].toInt() and 255
        val flg = input[1].toInt() and 255

        if (
            (cmf and 15) != 8 ||
            ((cmf shl 8) + flg) % 31 != 0
        ) return null

        return decompress("ZLIB", input) {
            InflaterInputStream(it)
        }
    }

    private fun decodeCommonsCompression(input: ByteArray): Result? =
        runCatching {
            val stream: CompressorInputStream =
                CompressorStreamFactory()
                    .createCompressorInputStream(
                        ByteArrayInputStream(input)
                    )

            val bytes = readLimited(stream, MAX_OUTPUT)

            if (bytes.isEmpty()) {
                null
            } else {
                Result(
                    "Commons Compress",
                    bytes,
                    "Compression stream decoded",
                    97
                )
            }
        }.getOrNull()

    private fun decompress(
        name: String,
        input: ByteArray,
        factory: (ByteArrayInputStream) -> InputStream
    ): Result? =
        runCatching {
            val bytes = readLimited(
                factory(ByteArrayInputStream(input)),
                MAX_OUTPUT
            )

            if (bytes.isEmpty()) {
                null
            } else {
                Result(
                    name,
                    bytes,
                    "$name decompressed",
                    98
                )
            }
        }.getOrNull()

    private fun inspectArchive(
        input: ByteArray,
        depth: Int
    ): List<Result> {
        if (depth >= MAX_DEPTH || !isArchive(input)) {
            return emptyList()
        }

        val results = mutableListOf<Result>()

        runCatching {
            ArchiveStreamFactory()
                .createArchiveInputStream(
                    ByteArrayInputStream(input)
                )
                .use { archive ->

                    var count = 0

                    while (count++ < MAX_CHILDREN) {
                        val entry = archive.nextEntry ?: break

                        if (entry.isDirectory) continue

                        val bytes = readLimited(
                            archive,
                            MAX_CHILD
                        )

                        if (bytes.isEmpty()) continue

                        val sig = signature(bytes)

                        val nested =
                            if (depth + 1 < MAX_DEPTH) {
                                runInternal(bytes, depth + 1)
                            } else {
                                emptyList()
                            }

                        results += Result(
                            name = "Archive entry: ${entry.name}",
                            bytes = bytes,
                            description =
                                "Extracted archive entry" +
                                    (sig?.first?.let { ": $it" } ?: ""),
                            confidence = 96,
                            detectedFormat = sig?.first,
                            mime = sig?.second,
                            children = nested
                        )
                    }
                }
        }

        return results
    }

    private fun signature(
        b: ByteArray
    ): Pair<String, String>? =
        when {
            starts(
                b,
                byteArrayOf(
                    0x89.toByte(), 0x50, 0x4e, 0x47,
                    0x0d, 0x0a, 0x1a, 0x0a
                )
            ) ->
                "PNG" to "image/png"

            starts(
                b,
                "%PDF-".toByteArray()
            ) ->
                "PDF" to "application/pdf"

            starts(
                b,
                "PK\u0003\u0004"
                    .toByteArray(StandardCharsets.ISO_8859_1)
            ) ->
                "ZIP" to "application/zip"

            starts(
                b,
                byteArrayOf(
                    0x1f.toByte(),
                    0x8b.toByte(),
                    0x08.toByte()
                )
            ) ->
                "GZIP" to "application/gzip"

            starts(
                b,
                byteArrayOf(
                    0x37, 0x7a, 0xbc.toByte(),
                    0xaf.toByte(), 0x27, 0x1c
                )
            ) ->
                "7-Zip" to "application/x-7z-compressed"

            starts(
                b,
                "Rar!\u001a\u0007"
                    .toByteArray(StandardCharsets.ISO_8859_1)
            ) ->
                "RAR" to "application/x-rar-compressed"

            starts(
                b,
                "SQLite format 3\u0000"
                    .toByteArray(StandardCharsets.ISO_8859_1)
            ) ->
                "SQLite" to "application/vnd.sqlite3"

            starts(
                b,
                byteArrayOf(
                    0x7f, 0x45, 0x4c, 0x46
                )
            ) ->
                "ELF" to "application/x-elf"

            starts(
                b,
                byteArrayOf(
                    0x4d, 0x5a
                )
            ) ->
                "PE" to
                    "application/vnd.microsoft.portable-executable"

            starts(
                b,
                "dex\n".toByteArray()
            ) ->
                "DEX" to "application/vnd.android.dex"

            starts(
                b,
                byteArrayOf(
                    0xff.toByte(),
                    0xd8.toByte(),
                    0xff.toByte()
                )
            ) ->
                "JPEG" to "image/jpeg"

            starts(
                b,
                "GIF87a".toByteArray()
            ) ||
                starts(
                    b,
                    "GIF89a".toByteArray()
                ) ->
                "GIF" to "image/gif"

            starts(
                b,
                "fLaC".toByteArray()
            ) ->
                "FLAC" to "audio/flac"

            starts(
                b,
                "OggS".toByteArray()
            ) ->
                "Ogg" to "application/ogg"

            starts(
                b,
                "RIFF".toByteArray()
            ) &&
                b.size >= 12 &&
                b.copyOfRange(8, 12)
                    .contentEquals("WAVE".toByteArray()) ->
                "WAV" to "audio/wav"

            starts(
                b,
                "RIFF".toByteArray()
            ) &&
                b.size >= 12 &&
                b.copyOfRange(8, 12)
                    .contentEquals("WEBP".toByteArray()) ->
                "WebP" to "image/webp"

            else -> null
        }

    private fun isArchive(b: ByteArray): Boolean =
        starts(
            b,
            "PK\u0003\u0004"
                .toByteArray(StandardCharsets.ISO_8859_1)
        ) ||
            starts(
                b,
                "!<arch>".toByteArray()
            ) ||
            starts(
                b,
                "ustar".toByteArray()
            )

    private fun plausible(b: ByteArray): Boolean {
        if (b.size < 4) return false

        if (signature(b) != null) return true

        val printable =
            b.count {
                it.toInt() in 0x20..0x7e ||
                    it == 9.toByte() ||
                    it == 10.toByte() ||
                    it == 13.toByte()
            }.toDouble() / b.size

        return printable >= 0.55
    }

    private fun readLimited(
        input: InputStream,
        limit: Int
    ): ByteArray {
        input.use { stream ->
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            var total = 0

            while (true) {
                val n = stream.read(buffer)

                if (n <= 0) break

                total += n

                if (total > limit) {
                    return ByteArray(0)
                }

                out.write(buffer, 0, n)
            }

            return out.toByteArray()
        }
    }

    private fun starts(
        b: ByteArray,
        prefix: ByteArray
    ): Boolean =
        b.size >= prefix.size &&
            b.copyOfRange(0, prefix.size)
                .contentEquals(prefix)
}
