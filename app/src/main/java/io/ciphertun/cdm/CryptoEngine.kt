package io.ciphertun.cdm

import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoEngine {
    private const val MAGIC = "CDM2"
    private const val SALT = 16
    private const val IV = 12
    private const val KEY = 32
    private const val ITERATIONS = 210_000
    private const val BUFFER = 64 * 1024

    fun encrypt(input: InputStream, output: OutputStream, password: CharArray) {
        val salt = ByteArray(SALT).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV).also { SecureRandom().nextBytes(it) }
        output.write(MAGIC.toByteArray()); output.write(salt); output.write(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, derive(password, salt), GCMParameterSpec(128, iv))
        val buf = ByteArray(BUFFER)
        while (true) { val n = input.read(buf); if (n <= 0) break; val out = cipher.update(buf, 0, n); if (out != null) output.write(out) }
        cipher.doFinal()?.let { output.write(it) }
    }

    fun decrypt(input: InputStream, output: OutputStream, password: CharArray) {
        require(input.readNBytes(4).decodeToString() == MAGIC) { "Not a CD Manager encrypted file" }
        val salt = input.readNBytes(SALT); require(salt.size == SALT)
        val iv = input.readNBytes(IV); require(iv.size == IV)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, derive(password, salt), GCMParameterSpec(128, iv))
        val buf = ByteArray(BUFFER)
        while (true) { val n = input.read(buf); if (n <= 0) break; val out = cipher.update(buf, 0, n); if (out != null) output.write(out) }
        cipher.doFinal()?.let { output.write(it) }
    }

    private fun derive(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY * 8)
        return try { SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded, "AES") } finally { spec.clearPassword() }
    }
}
