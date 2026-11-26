package com.clearscan

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Authenticated encryption for private document files.
 *
 * Format: 4-byte magic ("CSG2") || 12-byte GCM IV || AES-GCM ciphertext + 128-bit tag; the magic is authenticated as AAD.
 * The AES-256 key is generated and retained by Android Keystore and is never exported.
 */
object DocumentCrypto {
    private const val KEY_ALIAS = "clearscan.documents.aesgcm.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private val MAGIC = byteArrayOf(0x43, 0x53, 0x47, 0x32) // CSG2
    private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    private val PDF_SIGNATURE = "%PDF".toByteArray(Charsets.US_ASCII)

    @Synchronized
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    fun isEncrypted(file: File): Boolean {
        if (!file.isFile || file.length() < MAGIC.size) return false
        return runCatching {
            val header = ByteArray(12)
            val count = FileInputStream(file).use { input ->
                var total = 0
                while (total < header.size) {
                    val read = input.read(header, total, header.size - total)
                    if (read < 0) break
                    total += read
                }
                total
            }
            if (count >= MAGIC.size && header.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
                return@runCatching true
            }
            // If an attacker damages the encrypted marker, do not silently treat ciphertext as a legacy image/PDF.
            when (file.extension.lowercase()) {
                "jpg", "jpeg" -> !(count >= 3 && header[0] == 0xFF.toByte() && header[1] == 0xD8.toByte() && header[2] == 0xFF.toByte())
                "png" -> !(count >= PNG_SIGNATURE.size && header.copyOfRange(0, PNG_SIGNATURE.size).contentEquals(PNG_SIGNATURE))
                "webp" -> !(count >= 12 && header.copyOfRange(0, 4).contentEquals("RIFF".toByteArray()) && header.copyOfRange(8, 12).contentEquals("WEBP".toByteArray()))
                "bmp" -> !(count >= 2 && header[0] == 'B'.code.toByte() && header[1] == 'M'.code.toByte())
                "pdf" -> !(count >= PDF_SIGNATURE.size && header.copyOfRange(0, PDF_SIGNATURE.size).contentEquals(PDF_SIGNATURE))
                else -> false
            }
        }.getOrDefault(false)
    }

    fun encryptFile(source: File, destination: File) {
        require(source.isFile) { "Source document does not exist" }
        require(source.canonicalFile != destination.canonicalFile) { "Use encryptInPlace for in-place encryption" }
        destination.parentFile?.mkdirs()
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        cipher.updateAAD(MAGIC)
        val iv = cipher.iv ?: error("Android Keystore did not provide a GCM IV")
        require(iv.size == IV_BYTES) { "Unexpected AES-GCM IV length" }
        val temporary = File(destination.parentFile, ".${destination.name}.${UUID.randomUUID()}.enc-tmp")
        try {
            FileInputStream(source).use { input ->
                FileOutputStream(temporary).use { output ->
                    output.write(MAGIC)
                    output.write(iv)
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        cipher.update(buffer, 0, count)?.let(output::write)
                    }
                    output.write(cipher.doFinal())
                    output.fd.sync()
                }
            }
            android.system.Os.rename(temporary.absolutePath, destination.absolutePath)
        } finally {
            temporary.delete()
        }
    }

    fun decryptFile(source: File, destination: File) {
        require(isEncrypted(source)) { "Document is not in the encrypted ClearScan format" }
        destination.parentFile?.mkdirs()
        val temporary = File(destination.parentFile, ".${destination.name}.${UUID.randomUUID()}.plain-tmp")
        try {
            FileInputStream(source).use { stream ->
                val input = DataInputStream(stream)
                val magic = ByteArray(MAGIC.size)
                input.readFully(magic)
                check(magic.contentEquals(MAGIC)) { "Invalid encrypted document header" }
                val iv = ByteArray(IV_BYTES)
                input.readFully(iv)
                val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv))
                }
                FileOutputStream(temporary).use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        cipher.update(buffer, 0, count)?.let(output::write)
                    }
                    // GCM tag validation occurs here. The destination remains unpublished until this succeeds.
                    output.write(cipher.doFinal())
                    output.fd.sync()
                }
            }
            android.system.Os.rename(temporary.absolutePath, destination.absolutePath)
        } finally {
            temporary.delete()
        }
    }

    fun encryptInPlace(file: File) {
        if (isEncrypted(file)) return
        val temporary = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.enc")
        try {
            encryptFile(file, temporary)
            // Same-directory rename is atomic on Android/Linux and replaces the plaintext inode.
            android.system.Os.rename(temporary.absolutePath, file.absolutePath)
        } finally {
            temporary.delete()
        }
    }

    fun decryptedCacheCopy(context: Context, source: File): File {
        require(source.isFile) { "Document does not exist" }
        val copy = File(context.cacheDir, "clear-doc-${UUID.randomUUID()}-${source.name}")
        try {
            if (isEncrypted(source)) {
                decryptFile(source, copy)
            } else {
                source.copyTo(copy, overwrite = true)
                // Keep explicit export possible if a low-storage device temporarily blocks migration.
                if (isPrivateAppFile(context, source)) {
                    runCatching { encryptInPlace(source) }
                        .onFailure { AppLogger.e("Security", "Unable to migrate a legacy document during export", it) }
                }
            }
            return copy
        } catch (error: Throwable) {
            copy.delete()
            throw error
        }
    }

    fun withPlaintextFile(context: Context, source: File, block: (File) -> Unit) {
        require(source.isFile) { "Document does not exist" }
        if (isEncrypted(source)) {
            val temporary = File(context.cacheDir, "clear-read-${UUID.randomUUID()}-${source.name}")
            try {
                decryptFile(source, temporary)
                block(temporary)
            } finally {
                temporary.delete()
            }
        } else {
            block(source)
            // Backward-compatible lazy migration for existing app-private documents.
            if (isPrivateAppFile(context, source)) {
                runCatching { encryptInPlace(source) }
                    .onFailure { AppLogger.e("Security", "Unable to migrate a legacy document after read", it) }
            }
        }
    }

    private fun isPrivateAppFile(context: Context, file: File): Boolean {
        val path = runCatching { file.canonicalPath }.getOrNull() ?: return false
        val roots = listOfNotNull(context.filesDir, context.getExternalFilesDir(null))
            .mapNotNull { runCatching { it.canonicalPath }.getOrNull() }
        return roots.any { root -> path.startsWith(root + File.separator) || path == root }
    }
}
