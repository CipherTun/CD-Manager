package io.ciphertun.cdm

import io.ciphertun.cdm.backend.android.AndroidPlatformBackend
import io.ciphertun.cdm.backend.archive.ArchiveBackend
import io.ciphertun.cdm.backend.format.FormatBackend
import io.ciphertun.cdm.backend.java.JavaCrypto
import io.ciphertun.cdm.backend.kotlin.KotlinCore
import io.ciphertun.cdm.backend.msgpack.MessagePackBackend
import io.ciphertun.cdm.backend.protocol.ProtocolBackend

/** Central capability router. It selects and invokes only an engine that supports the requested job. */
object EngineRouter {
    enum class Job { FILE_ACCESS, HASH_METRICS, FORMAT_IDENTITY, PROTOCOL_IDENTITY, ARCHIVE, MESSAGEPACK, CRYPTO, DARK_TUNNEL, EXTERNAL_PARITY }
    data class Backend(val id:String, val name:String, val runtime:String, val available:Boolean, val jobs:Set<Job>)

    private val backends = listOf(
        Backend("kotlin", "Kotlin Core Backend", "android", KotlinCore.available(), setOf(Job.FILE_ACCESS, Job.CRYPTO)),
        Backend("go", "Go Native Backend", "android", GoBackend.available(), setOf(Job.HASH_METRICS)),
        Backend("java", "Java/JCA Backend", "android", true, setOf(Job.CRYPTO, Job.HASH_METRICS)),
        Backend("archive", "Apache Commons Compress Backend", "android", ArchiveBackend.available(), setOf(Job.ARCHIVE)),
        Backend("msgpack", "MessagePack Backend", "android", MessagePackBackend.available(), setOf(Job.MESSAGEPACK)),
        Backend("android", "Android Platform / SAF Backend", "android", AndroidPlatformBackend.available(), setOf(Job.FILE_ACCESS)),
        Backend("format", "Format Intelligence Backend", "android", FormatBackend.available(), setOf(Job.FORMAT_IDENTITY)),
        Backend("protocol", "Protocol Intelligence Backend", "android", ProtocolBackend.available(), setOf(Job.PROTOCOL_IDENTITY)),
        Backend("node", "Node.js Parity Backend", "ci-desktop", true, setOf(Job.EXTERNAL_PARITY)),
        Backend("python", "Python Parity Backend", "ci-desktop", true, setOf(Job.EXTERNAL_PARITY))
    )

    fun all(): List<Backend> = backends
    fun select(job: Job, androidOnly: Boolean = true): Backend? = backends.firstOrNull {
        it.available && job in it.jobs && (!androidOnly || it.runtime == "android")
    }
    fun plan(vararg jobs: Job): List<Backend> = jobs.mapNotNull { select(it) }.distinctBy { it.id }

    fun identifyFormat(name: String, sample: ByteArray) = FormatBackend.identify(name, sample)
    fun detectProtocols(text: String) = ProtocolBackend.detect(text)
    fun archiveFormat(sample: ByteArray) = ArchiveBackend.detect(sample)
    fun decodeMessagePack(bytes: ByteArray) = MessagePackBackend.decode(bytes)
    fun sha256(bytes: ByteArray): String = runCatching { JavaCrypto.sha256(bytes) }.getOrElse { GoBackend.analyze(bytes)?.sha256 ?: "" }
}
