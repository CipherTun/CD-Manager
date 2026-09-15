package io.ciphertun.cdm

import android.content.ContentResolver
import android.net.Uri
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import kotlin.math.log2

object Analyzer {
    fun analyze(resolver: ContentResolver, uri: Uri, displayName: String): FileReport {
        val ext = displayName.substringAfterLast('.', "").lowercase(Locale.ROOT)
        val spec = FormatRegistry.lookup(ext)
        val sample = resolver.openInputStream(uri)?.use { it.readNBytes(1024 * 1024) } ?: ByteArray(0)
        val magic = detectMagic(sample)
        val universal = UniversalDecoder.run(sample)
        val bestDecoded = universal.firstOrNull()
        val decodedMagic = bestDecoded?.let { detectMagic(it.bytes) }
        val jobs = mutableListOf(EngineRouter.Job.HASH_METRICS, EngineRouter.Job.FORMAT_IDENTITY, EngineRouter.Job.PROTOCOL_IDENTITY)
        if (ext in setOf("zip", "7z", "tar", "gz", "bz2", "xz", "zst", "rar")) jobs += EngineRouter.Job.ARCHIVE
        if (ext == "dark" || sample.toString(Charsets.UTF_8).contains("darktunnel://", true)) jobs += EngineRouter.Job.DARK_TUNNEL
        val plan = EngineRouter.plan(*jobs.toTypedArray())
        val goMetrics = if (GoBackend.available()) GoBackend.analyze(sample) else null
        val dark = if (ext == "dark" || sample.toString(Charsets.UTF_8).contains("darktunnel://", true)) DarkTunnel.tryDecrypt(sample) else null
        val decodedDark = if (dark == null) universal.asSequence().mapNotNull { DarkTunnel.tryDecrypt(it.bytes) }.firstOrNull() else null
        val effectiveDark = dark ?: decodedDark
        val identity = AppIdentityEngine.identify(displayName, sample, ext)
        val routedFormat = EngineRouter.identifyFormat(displayName, sample)
        val archiveEngine = if (EngineRouter.select(EngineRouter.Job.ARCHIVE) != null) EngineRouter.archiveFormat(sample) else null
        val format = when {
            effectiveDark != null -> "Dark Tunnel configuration (decrypted)"
            routedFormat != null -> routedFormat.name
            archiveEngine != null -> "Archive (${archiveEngine.removeSuffix("InputStream")})"
            magic != null && identity.appName == "Unknown application" -> magic
            decodedMagic != null && identity.appName == "Unknown application" -> "Decoded container → $decodedMagic"
            bestDecoded != null && identity.appName == "Unknown application" -> "Decoded container → ${bestDecoded.name}"
            else -> identity.formatName
        }
        val protocolSeed = buildString {
            append(sample.toString(Charsets.ISO_8859_1))
            if (effectiveDark != null) append("\n").append(effectiveDark.raw)
            if (bestDecoded != null) append("\n").append(bestDecoded.bytes.toString(Charsets.UTF_8))
        }
        val protocols = EngineRouter.detectProtocols(protocolSeed).ifEmpty { ProtocolDetector.detect(protocolSeed) }
        val mime = guessMime(format, ext)
        val sha = digest(resolver.openInputStream(uri) ?: error("Unable to open file"), "SHA-256")
        val sha1 = digest(resolver.openInputStream(uri) ?: error("Unable to open file"), "SHA-1")
        val md5 = digest(resolver.openInputStream(uri) ?: error("Unable to open file"), "MD5")
        val fields = mutableListOf<Pair<String,String>>()
        fields += "Extension" to if (ext.isEmpty()) "none" else ".${ext}"
        fields += "Application" to if (effectiveDark != null) "Dark Tunnel" else identity.appName
        fields += "Detected format" to format
        fields += "Universal decoder candidates" to if (universal.isEmpty()) "None" else universal.joinToString(", ") { "${it.name} (${it.confidence}%)" }
        if (protocols.isNotEmpty()) fields += "Protocols / transports" to protocols.joinToString(", ")
        fields += "MIME" to mime
        fields += "Detection confidence" to if (magic != null || effectiveDark != null || decodedMagic != null) "High" else if (spec != null || bestDecoded != null) "Medium" else "Low"
        fields += "File size" to humanSize(querySize(resolver, uri))
        fields += "SHA-256" to sha
        fields += "SHA-1" to sha1
        fields += "MD5" to md5
        fields += "Entropy (sample)" to "%.2f bits/byte".format(goMetrics?.entropy ?: entropy(sample))
        fields += "Printable text" to "%.1f%%".format(goMetrics?.printablePercent ?: printableRatio(sample) * 100)
        fields += "Backend router" to plan.joinToString(", ") { it.name }
        fields += "Routed format engine" to (routedFormat?.let { "${it.name} (${it.evidence})" } ?: "No specialized format engine match")
        if (archiveEngine != null) fields += "Archive engine" to archiveEngine
        fields += "Analysis engine" to if (goMetrics != null) "Go high-speed engine + Android streaming engine" else "Android streaming engine"
        if (spec != null) fields += "Format adapter" to spec.status
        if (effectiveDark != null) fields += "Decryption" to "Successful — fields extracted locally"
        else if (bestDecoded != null) fields += "Decoding" to "Successful — ${bestDecoded.description}; original file was not modified"
        if (spec?.family?.contains("VPN", true) == true && effectiveDark == null) fields += "Decryption" to "Format recognized; protected/proprietary variants require a verified adapter/key"
        val notes = mutableListOf("All analysis runs locally on the device.")
        if (effectiveDark != null) notes += "Decrypted configuration is displayed in full when the verified Dark Tunnel adapter can recover it."
        if (bestDecoded != null) notes += "Universal decoding runs multiple reversible decoders in parallel and reports only validated byte output."
        if (spec != null && effectiveDark == null && spec.family.contains("VPN")) notes += "This extension is recognized, but recognition is not the same as decryption. Unsupported/protected variants are reported honestly."
        val encrypted = looksEncrypted(sample, ext)
        return FileReport(
            name = displayName, size = querySize(resolver, uri), extension = ext, mime = mime, format = format, application = if (effectiveDark != null) "Dark Tunnel" else identity.appName, protocols = protocols,
            confidence = when { effectiveDark != null -> 99; identity.appName != "Unknown application" -> identity.confidence; magic != null || decodedMagic != null -> 85; spec != null || bestDecoded != null -> 70; else -> 25 }, encrypted = encrypted,
            sha256 = sha, fields = if (effectiveDark != null) fields + effectiveDark.fields else fields,
            notes = notes, rawText = effectiveDark?.raw ?: bestDecoded?.bytes?.toString(Charsets.UTF_8)?.takeIf { looksUsefulText(it) }, stringsPreview = extractStrings(sample), hexPreview = hex(sample, 384),
            adapterStatus = when { effectiveDark != null -> "Decrypted"; bestDecoded != null -> "Decoded (${bestDecoded.name})"; identity.appName != "Unknown application" -> identity.status; else -> spec?.status ?: "Generic analyzer" },
            warnings = if (sample.isEmpty()) listOf("The file could not be read.") else emptyList()
        )
    }

    private fun querySize(r: ContentResolver, u: Uri): Long = try { r.openAssetFileDescriptor(u, "r")?.use { it.length } ?: -1L } catch (_: Exception) { -1L }
    private fun digest(input: InputStream, algorithm: String): String = input.use { ins ->
        val md = MessageDigest.getInstance(algorithm); val buf = ByteArray(64 * 1024)
        while (true) { val n = ins.read(buf); if (n <= 0) break; md.update(buf, 0, n) }
        md.digest().joinToString("") { "%02x".format(it) }
    }
    private fun detectMagic(b: ByteArray): String? = when {
        b.size >= 8 && b.copyOfRange(0,8).contentEquals(byteArrayOf(0x89.toByte(),0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)) -> "PNG image"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x50,0x4b,0x03,0x04)) -> "ZIP / ZIP-based container"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x25,0x50,0x44,0x46)) -> "PDF document"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x1f,0x8b.toByte(),0x08,0x00)) -> "GZIP"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x28,0xb5.toByte(),0x2f,0xfd.toByte())) -> "Zstandard"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x7f,0x45,0x4c,0x46)) -> "ELF binary"
        b.size >= 2 && b.copyOfRange(0,2).contentEquals(byteArrayOf(0x4d,0x5a)) -> "PE executable"
        b.size >= 4 && b.copyOfRange(0,4).contentEquals(byteArrayOf(0x64,0x65,0x78,0x0a)) -> "DEX executable"
        b.size >= 16 && b.copyOfRange(0,16).toString(Charsets.US_ASCII).startsWith("SQLite format 3") -> "SQLite database"
        else -> null
    }
    private fun guessMime(format: String, ext: String): String = when {
        format.startsWith("ZIP") -> "application/zip"; format == "PDF document" -> "application/pdf"; format == "GZIP" -> "application/gzip"
        format == "PNG image" -> "image/png"; ext in setOf("json") -> "application/json"; ext in setOf("xml") -> "application/xml"
        ext in setOf("jpg","jpeg") -> "image/jpeg"; ext == "apk" -> "application/vnd.android.package-archive"; else -> "application/octet-stream"
    }
    private fun looksEncrypted(b: ByteArray, ext: String): Boolean { if (b.isEmpty()) return false; return printableRatio(b) < .18 && ext !in setOf("png","jpg","jpeg","zip","gz","7z","pdf") }
    private fun printableRatio(b: ByteArray): Double = if (b.isEmpty()) 0.0 else b.count { it.toInt() in 0x20..0x7e || it == 0x0a.toByte() || it == 0x0d.toByte() || it == 0x09.toByte() }.toDouble() / b.size
    private fun entropy(b: ByteArray): Double { if (b.isEmpty()) return 0.0; val counts = IntArray(256); b.forEach { counts[it.toInt() and 255]++ }; return counts.filter { it > 0 }.sumOf { val p = it.toDouble()/b.size; -p*log2(p) } }
    private fun extractStrings(b: ByteArray): List<String> = b.toString(Charsets.ISO_8859_1).split(Regex("[^\\x20-\\x7E]{2,}" )).flatMap { it.split(Regex("[^\\x20-\\x7E]+")) }.filter { it.length >= 4 }.distinct().take(80)
    private fun hex(b: ByteArray, max: Int): String = b.take(max).chunked(16).mapIndexed { i, row -> "%08x  %s".format(i*16, row.joinToString(" ") { "%02x".format(it) }) }.joinToString("\n")
    private fun looksUsefulText(text: String): Boolean {
        val t = text.trim()
        return t.length >= 4 && t.count { it == '\uFFFD' } == 0 && t.count { it.isLetterOrDigit() || it.isWhitespace() || it in "{}[]:=,./_-" }.toDouble() / t.length > .78
    }
    private fun humanSize(n: Long): String { if (n < 0) return "unknown"; if (n < 1024) return "$n B"; if (n < 1024*1024) return "%.1f KiB".format(n/1024.0); if (n < 1024L*1024*1024) return "%.1f MiB".format(n/(1024.0*1024)); return "%.2f GiB".format(n/(1024.0*1024*1024)) }
}
