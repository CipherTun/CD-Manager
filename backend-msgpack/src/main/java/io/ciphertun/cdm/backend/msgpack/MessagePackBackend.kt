package io.ciphertun.cdm.backend.msgpack

import java.io.ByteArrayInputStream

/** Small self-contained MessagePack decoder for config containers. */
object MessagePackBackend {
    const val NAME = "MessagePack Backend"
    fun available() = true
    fun decode(bytes: ByteArray): Any? = Decoder(bytes).read()

    private class Decoder(private val b: ByteArray) {
        private var p = 0
        private fun need(n: Int) { require(n >= 0 && p + n <= b.size) { "Truncated MessagePack input" } }
        private fun u8(): Int { need(1); return b[p++].toInt() and 255 }
        private fun u16(): Int = (u8() shl 8) or u8()
        private fun u32(): Int = (u8() shl 24) or (u8() shl 16) or (u8() shl 8) or u8()
        private fun bytes(n: Int): ByteArray { need(n); return b.copyOfRange(p, p + n).also { p += n } }
        private fun str(n: Int) = bytes(n).toString(Charsets.UTF_8)
        fun read(): Any? {
            val c = u8()
            return when {
                c <= 0x7f -> c
                c >= 0xe0 -> c - 256
                c in 0xa0..0xbf -> str(c and 31)
                c in 0x90..0x9f -> List(c and 15) { read() }
                c in 0x80..0x8f -> map(c and 15)
                c == 0xc0 -> null
                c == 0xc2 -> false
                c == 0xc3 -> true
                c == 0xcc -> u8()
                c == 0xcd -> u16()
                c == 0xce -> u32().toLong() and 0xffffffffL
                c == 0xcf -> readU64()
                c == 0xd0 -> u8().toByte().toInt()
                c == 0xd1 -> signed16()
                c == 0xd2 -> u32()
                c == 0xd3 -> signed64()
                c == 0xca -> Float.fromBits(u32())
                c == 0xcb -> Double.fromBits(signed64())
                c == 0xc4 -> bytes(u8())
                c == 0xc5 -> bytes(u16())
                c == 0xc6 -> bytes(u32())
                c == 0xd9 -> str(u8())
                c == 0xda -> str(u16())
                c == 0xdb -> str(u32())
                c == 0xdc -> List(u16()) { read() }
                c == 0xdd -> List(u32()) { read() }
                c == 0xde -> map(u16())
                c == 0xdf -> map(u32())
                else -> error("Unsupported MessagePack token 0x${c.toString(16)}")
            }
        }
        private fun map(n: Int): MutableMap<String, Any?> { val out = linkedMapOf<String, Any?>(); repeat(n) { out[read().toString()] = read() }; return out }
        private fun signed16(): Int { val x=u16(); return if(x and 0x8000 != 0) x-65536 else x }
        private fun signed64(): Long { var x=0L; repeat(8){x=(x shl 8) or u8().toLong()}; return x }
        private fun readU64() = signed64()
    }
}
