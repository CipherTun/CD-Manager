package io.ciphertun.cdm.backend.archive

import org.apache.commons.compress.archivers.ArchiveInputStream
import org.apache.commons.compress.archivers.ArchiveStreamFactory
import java.io.ByteArrayInputStream

object ArchiveBackend {
    const val NAME = "Apache Commons Compress Backend"

    fun available(): Boolean = true

    fun detect(bytes: ByteArray): String? {
        return try {
            ByteArrayInputStream(bytes).use { input ->
                val reader: ArchiveInputStream<*> =
                    ArchiveStreamFactory().createArchiveInputStream(input)
                reader.javaClass.simpleName
            }
        } catch (_: Exception) {
            null
        }
    }
}
