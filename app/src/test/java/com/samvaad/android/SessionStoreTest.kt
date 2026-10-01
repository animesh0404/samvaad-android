package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.PersistedSession
import com.samvaad.android.session.SessionStore
import com.samvaad.android.session.SessionStoreException
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Session-store unit tests: envelope round-trip, record contents, and
 * fail-closed handling. The wrapping key is ephemeral (test-only stand-in
 * for the Keystore key); custody itself is covered by instrumented tests.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SessionStoreTest {

    private class EphemeralKeys(var present: Boolean = true) : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = if (present) key else null
    }

    private lateinit var context: Context
    private lateinit var keys: EphemeralKeys

    private fun store(): FileSessionStore = FileSessionStore(context, keys)

    private fun record() = PersistedSession(
        serverAddress = "https://example.test:8080",
        identifier = "alice",
        refreshToken = "refresh-test-token-value",
        sessionId = "11111111-2222-3333-4444-555555555555",
        refreshExpiresAtEpochMillis = 9_999_999_999_999L,
    )

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
        keys = EphemeralKeys()
    }

    @Test
    fun roundTrip_preservesAllFields() {
        store().save(record())
        assertEquals(record(), store().load())
    }

    @Test
    fun persistedRecord_containsRequiredFields() {
        store().save(record())
        val loaded = store().load()!!
        assertEquals("https://example.test:8080", loaded.serverAddress)
        assertEquals("alice", loaded.identifier)
        assertEquals("refresh-test-token-value", loaded.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", loaded.sessionId)
        assertEquals(9_999_999_999_999L, loaded.refreshExpiresAtEpochMillis)
    }

    @Test
    fun storedFile_containsNoSecrets() {
        store().save(record())
        val bytes = FileSessionStore.rawFile(context).readBytes()
        val text = String(bytes, Charsets.UTF_8)
        // The refresh token must never appear as plaintext; neither may an
        // access token or password, which have no field here by construction.
        assertFalse(text.contains("refresh-test-token-value"))
        assertFalse(text.contains("access-test-token-value"))
        assertFalse(text.contains("s3cr3t"))
        // Envelope structure is inspectable without plaintext: magic + version.
        assertEquals(0x53.toByte(), bytes[0])
        assertEquals(0x56.toByte(), bytes[1])
        assertEquals(0x4C.toByte(), bytes[2])
        assertEquals(0x54.toByte(), bytes[3])
    }

    @Test
    fun save_replacesAtomically() {
        store().save(record())
        val updated = record().copy(refreshToken = "rotated-token-value")
        store().save(updated)
        assertEquals(updated, store().load())
    }

    @Test
    fun clear_removesRecord() {
        store().save(record())
        store().clear()
        assertNull(store().load())
        store().clear() // idempotent
    }

    @Test
    fun missingFile_loadsNull() {
        assertNull(store().load())
    }

    @Test
    fun corruptFile_failsClosed() {
        FileSessionStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeBytes(byteArrayOf(0x01, 0x02, 0x03))
        }
        assertThrows(SessionStoreException::class.java) {
            store().load()
        }
    }

    @Test
    fun unknownSchema_rejected() {
        // Forge a well-formed envelope carrying an unknown schema version.
        val forged = """
            {"schemaVersion":999,"serverAddress":"https://example.test:8080",
             "identifier":"alice","refreshToken":"x","sessionId":"11111111-2222-3333-4444-555555555555",
             "refreshExpiresAtEpochMillis":1}
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val key = keys.getOrCreate()
        val envelope = com.samvaad.android.crypto.RecordEnvelopeCodec.seal(
            key,
            FileSessionStore.SESSION_KIND,
            FileSessionStore.SESSION_HANDLE_ID,
            forged,
        )
        FileSessionStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeBytes(envelope)
        }
        assertThrows(SessionStoreException::class.java) {
            store().load()
        }
    }

    @Test
    fun missingKey_failsClosed() {
        store().save(record())
        keys.present = false
        val failure = try {
            store().load()
            null
        } catch (e: SessionStoreException) {
            e
        }
        assertTrue(failure != null)
        assertTrue(failure!!.keyMissing)
    }

    @Test
    fun storedUnderNoBackupDir() {
        store().save(record())
        val file = FileSessionStore.rawFile(context)
        assertTrue(file.isFile)
        assertTrue(
            file.canonicalPath.startsWith(
                File(context.noBackupFilesDir, FileSessionStore.SUBDIR).canonicalPath
            )
        )
    }
}
