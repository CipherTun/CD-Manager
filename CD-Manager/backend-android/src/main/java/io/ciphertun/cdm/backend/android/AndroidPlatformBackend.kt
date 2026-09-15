package io.ciphertun.cdm.backend.android

import android.content.ContentResolver
import android.net.Uri
import java.io.InputStream

object AndroidPlatformBackend {
    const val NAME = "Android Platform / SAF Backend"
    fun available() = true
    fun open(resolver: ContentResolver, uri: Uri): InputStream? = resolver.openInputStream(uri)
    fun size(resolver: ContentResolver, uri: Uri): Long = runCatching {
        resolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
    }.getOrDefault(-1L)
}
