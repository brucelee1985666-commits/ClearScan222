package com.clearscan

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DocumentCryptoTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun encryptsAndDecryptsDocumentWithoutPlaintextOnDisk() {
        val source = File(context.cacheDir, "crypto-test-source.bin")
        val encrypted = File(context.cacheDir, "crypto-test-encrypted.bin")
        val decrypted = File(context.cacheDir, "crypto-test-decrypted.bin")
        val original = ByteArray(180_000) { (it * 31).toByte() }
        try {
            source.writeBytes(original)
            DocumentCrypto.encryptFile(source, encrypted)
            assertTrue(DocumentCrypto.isEncrypted(encrypted))
            assertFalse(encrypted.readBytes().contentEquals(original))
            DocumentCrypto.decryptFile(encrypted, decrypted)
            assertArrayEquals(original, decrypted.readBytes())
        } finally {
            source.delete()
            encrypted.delete()
            decrypted.delete()
        }
    }

    @Test
    fun rejectsModifiedCiphertext() {
        val source = File(context.cacheDir, "crypto-tamper-source.bin")
        val encrypted = File(context.cacheDir, "crypto-tamper-encrypted.bin")
        val decrypted = File(context.cacheDir, "crypto-tamper-decrypted.bin")
        try {
            source.writeText("private scan document")
            DocumentCrypto.encryptFile(source, encrypted)
            val bytes = encrypted.readBytes()
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x40).toByte()
            encrypted.writeBytes(bytes)
            var rejected = false
            try {
                DocumentCrypto.decryptFile(encrypted, decrypted)
            } catch (_: Exception) {
                rejected = true
            }
            assertTrue("GCM authentication must reject modified ciphertext", rejected)
            assertFalse(decrypted.exists() && decrypted.length() > 0)
        } finally {
            source.delete()
            encrypted.delete()
            decrypted.delete()
        }
    }
}
