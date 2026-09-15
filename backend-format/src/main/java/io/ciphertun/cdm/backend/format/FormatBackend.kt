package io.ciphertun.cdm.backend.format

import java.util.Locale

data class FormatMatch(val name: String, val evidence: String, val confidence: Int)

object FormatBackend {
    const val NAME = "Format Intelligence Backend"
    fun available() = true

    fun identify(displayName: String, bytes: ByteArray): FormatMatch? {
        val ext = displayName.substringAfterLast('.', "").lowercase(Locale.ROOT)
        val text = bytes.toString(Charsets.ISO_8859_1).lowercase(Locale.ROOT)
        val candidates = listOf(
            if (ext == "stk" && "starkvpn" in text) FormatMatch("Stark VPN", "Stark VPN content signature + .stk", 99) else null,
            if (ext == "hat" && ("hatunnel" in text || "ha tunnel" in text)) FormatMatch("HA Tunnel Plus", "HA Tunnel Plus content signature + .hat", 99) else null,
            if (ext == "ehi" && ("http injector" in text || "ehi" in text)) FormatMatch("HTTP Injector", "HTTP Injector content signature + .ehi", 99) else null,
            if (ext == "hc" && ("httpcustom" in text || "http custom" in text)) FormatMatch("HTTP Custom", "HTTP Custom content signature + .hc", 99) else null,
            if (ext == "ziv" && "zivpn" in text) FormatMatch("ZIVPN", "ZIVPN content signature + .ziv", 99) else null,
            if ("darktunnel://" in text || "encryptedlockedconfig" in text) FormatMatch("Dark Tunnel", "Dark Tunnel content signature", 99) else null
        ).filterNotNull()
        if (candidates.isNotEmpty()) return candidates.first()
        return when {
            starts(bytes, byteArrayOf(0x50,0x4b,0x03,0x04)) -> FormatMatch("ZIP / ZIP-based container", "ZIP magic", 99)
            starts(bytes, byteArrayOf(0x25,0x50,0x44,0x46)) -> FormatMatch("PDF document", "PDF magic", 99)
            starts(bytes, byteArrayOf(0x1f,0x8b.toByte(),0x08)) -> FormatMatch("GZIP", "GZIP magic", 99)
            bytes.size >= 8 && bytes.copyOfRange(0,8).contentEquals(byteArrayOf(0x89.toByte(),0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)) -> FormatMatch("PNG image", "PNG magic", 99)
            else -> null
        }
    }
    private fun starts(bytes: ByteArray, prefix: ByteArray) = bytes.size >= prefix.size && bytes.copyOfRange(0, prefix.size).contentEquals(prefix)
}
