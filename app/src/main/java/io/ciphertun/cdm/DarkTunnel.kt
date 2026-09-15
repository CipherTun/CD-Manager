package io.ciphertun.cdm

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Real parser for the public Dark Tunnel container format used by the research sample. */
object DarkTunnel {
    private val key256 = "\$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd".toByteArray(Charsets.UTF_8)
    private val key192 = "F)J@NcRfUjXn2r4u7x!A%D*G".toByteArray(Charsets.UTF_8)
    private val iv = hex("232e39185523184a5723586242200e05")

    fun tryDecrypt(input: ByteArray): DarkResult? = runCatching {
        var raw = input.toString(Charsets.UTF_8).trim()
        if (raw.contains("://")) raw = raw.substringAfter("://")
        val looksLikeContainer = raw.contains("encryptedLockedConfig", true) || raw.matches(Regex("[A-Za-z0-9+/=_-]{32,}"))
        if (!looksLikeContainer) return null
        val outerJson = JSONObject(base64Decode(raw).toString(Charsets.UTF_8))
        if (!outerJson.has("encryptedLockedConfig")) return null
        val outerEncrypted = base64Decode(outerJson.getString("encryptedLockedConfig"))
        val outerPlain = aesCfb(outerEncrypted, key256, iv)
        val outerMap = MsgPack.decode(outerPlain) as? Map<*, *> ?: return null
        val normalizedOuter = outerMap.toMutableMap()
        val locked = normalizedOuter.entries.firstOrNull { it.key.toString() == "EncryptedLockedConfig" }?.value
        if (locked is ByteArray) {
            val innerPlain = aesCfb(locked, key192, iv)
            val inner = MsgPack.decode(innerPlain)
            normalizedOuter["EncryptedLockedConfig"] = cleanEncrypted(inner, key192)
        }
        val merged = LinkedHashMap<String, Any?>()
        for ((k, v) in outerJson.toMap()) merged[k] = v
        merged["encryptedLockedConfig"] = cleanEncrypted(normalizedOuter, key192)
        val display = pretty(merged)
        val fields = extractFields(merged)
        DarkResult(fields, display)
    }.getOrNull()

    private fun cleanEncrypted(value: Any?, key: ByteArray): Any? = when (value) {
        is Map<*, *> -> value.entries.associate { (k, v) ->
            val ks = k.toString()
            ks to if (ks.startsWith("Encrypted", true) && v is ByteArray) {
                decodeBytes(aesCfb(v, key, iv))
            } else cleanEncrypted(v, key)
        }
        is List<*> -> value.map { cleanEncrypted(it, key) }
        is ByteArray -> decodeBytes(value)
        else -> value
    }

    private fun decodeBytes(bytes: ByteArray): Any {
        val text = bytes.toString(Charsets.UTF_8)
        return if (text.count { it == '\uFFFD' } == 0 && text.any { it.isLetterOrDigit() || it.isWhitespace() }) {
            parseJsonIfUseful(text) ?: text
        } else bytes.toHex()
    }

    private fun parseJsonIfUseful(text: String): Any? = runCatching {
        val t = text.trim()
        when {
            t.startsWith("{") -> jsonObjectToMap(JSONObject(t))
            t.startsWith("[") -> jsonArrayToList(JSONArray(t))
            else -> null
        }
    }.getOrNull()


    private fun pretty(value: Any?): String = when (value) {
        is Map<*, *> -> JSONObject(value.mapKeys { it.key.toString() }).toString(2)
        is List<*> -> JSONArray(value).toString(2)
        else -> value?.toString() ?: "null"
    }

    private fun extractFields(root: Map<String, Any?>): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        val interesting = listOf(
            "configType" to "Config type", "type" to "Type", "name" to "Name", "server" to "Server",
            "host" to "Host", "port" to "Port", "serverName" to "SNI / serverName", "sni" to "SNI",
            "proxy" to "Proxy", "payload" to "HTTP payload", "dns" to "DNS", "protocol" to "Protocol",
            "network" to "Network", "tls" to "TLS", "allowInsecure" to "Allow insecure", "ssh" to "SSH",
            "v2ray" to "V2Ray / Trojan", "mux" to "Mux", "security" to "Security", "flow" to "Flow"
        )
        fun walk(v: Any?, path: String = "") {
            when (v) {
                is Map<*, *> -> v.forEach { (k, x) ->
                    val key = k.toString()
                    val lower = key.lowercase()
                    val label = interesting.firstOrNull { lower == it.first.lowercase() || lower.contains(it.first.lowercase()) }?.second
                    if (label != null && x !is Map<*, *> && x !is List<*>) out += label to sanitize(x.toString())
                    walk(x, if (path.isEmpty()) key else "$path.$key")
                }
                is List<*> -> v.forEach { walk(it, path) }
            }
        }
        walk(root)
        val unique = LinkedHashMap<String, String>()
        out.forEach { unique.putIfAbsent(it.first, it.second) }
        return unique.entries.map { it.key to it.value }
    }

    private fun sanitize(s: String): String = if (s.length > 400) s.take(400) + "…" else s

    private fun aesCfb(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun base64Decode(s: String): ByteArray {
        val clean = s.trim().replace("-", "+").replace("_", "/")
        return runCatching { Base64.decode(clean, Base64.DEFAULT) }.getOrElse {
            java.util.Base64.getDecoder().decode(clean)
        }
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun JSONObject.toMap(): Map<String, Any?> = keys().asSequence().associateWith { k ->
        when (val v = get(k)) { JSONObject.NULL -> null; is JSONObject -> v.toMap(); is JSONArray -> jsonArrayToList(v); else -> v }
    }
    private fun jsonObjectToMap(o: JSONObject): Map<String, Any?> = o.toMap()
    private fun jsonArrayToList(a: JSONArray): List<Any?> = (0 until a.length()).map { i -> when (val v = a.get(i)) { JSONObject.NULL -> null; is JSONObject -> v.toMap(); is JSONArray -> jsonArrayToList(v); else -> v } }
}

data class DarkResult(val fields: List<Pair<String, String>>, val raw: String)

private object MsgPack {
    fun decode(bytes: ByteArray): Any? = Decoder(bytes).read()

    private class Decoder(private val b: ByteArray) {
        private var p = 0
        private fun u8() = b[p++].toInt() and 0xff
        private fun u16() = (u8() shl 8) or u8()
        private fun u32() = (u8() shl 24) or (u8() shl 16) or (u8() shl 8) or u8()
        private fun bytes(n: Int) = b.copyOfRange(p, p + n).also { p += n }
        private fun str(n: Int) = bytes(n).toString(Charsets.UTF_8)
        fun read(): Any? {
            val c = u8()
            return when {
                c <= 0x7f -> c
                c >= 0xe0 -> c - 256
                c in 0xa0..0xbf -> str(c and 0x1f)
                c in 0x90..0x9f -> List(c and 0x0f) { read() }
                c in 0x80..0x8f -> map(c and 0x0f)
                c == 0xc0 -> null
                c == 0xc2 -> false
                c == 0xc3 -> true
                c == 0xcc -> u8()
                c == 0xcd -> u16()
                c == 0xce -> u32().toLong() and 0xffffffffL
                c == 0xcf -> readU64()
                c == 0xd0 -> u8().toByte().toInt()
                c == 0xd1 -> readS16()
                c == 0xd2 -> u32()
                c == 0xd3 -> readS64()
                c == 0xca -> Float.fromBits(u32())
                c == 0xcb -> Double.fromBits(readS64())
                c == 0xc4 -> bytes(u8())
                c == 0xc5 -> bytes(u16())
                c == 0xc6 -> bytes(u32())
                c == 0xd9 -> str(u8())
                c == 0xda -> str(u16())
                c == 0xdb -> str(u32())
                c in 0xdc..0xdd -> { val n = if (c == 0xdc) u16() else u32(); List(n) { read() } }
                c in 0xde..0xdf -> map(if (c == 0xde) u16() else u32())
                else -> error("Unsupported MessagePack token 0x${c.toString(16)}")
            }
        }
        private fun map(n: Int): MutableMap<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            repeat(n) { out[read().toString()] = read() }
            return out
        }
        private fun readS16(): Int { val x = u16(); return if (x and 0x8000 != 0) x - 0x10000 else x }
        private fun readS64(): Long { var x = 0L; repeat(8) { x = (x shl 8) or u8().toLong() }; return x }
        private fun readU64(): Long = readS64()
    }
}
