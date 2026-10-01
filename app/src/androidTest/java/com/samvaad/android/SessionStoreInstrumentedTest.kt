package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.PersistedSession
import com.samvaad.android.session.SessionStoreException
import java.io.File
import java.security.KeyStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Session-store instrumented tests: real Android Keystore wrapping key
 * on this device's ABI. No network, no UI.
 */
@RunWith(AndroidJUnit4::class)
class SessionStoreInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun store() =
        FileSessionStore(context, AndroidKeystoreKeyProvider())

    private fun record() = PersistedSession(
        serverAddress = "https://example.test:8080",
        identifier = "alice",
        refreshToken = "refresh-instrumented-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
        refreshExpiresAtEpochMillis = System.currentTimeMillis() + 86_400_000,
    )

    @Before
    fun clean() {
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
    }

    @Test
    fun keystoreRoundTrip_recoversRecord() {
        store().save(record())
        val loaded = store().load()!!
        assertEquals(record().serverAddress, loaded.serverAddress)
        assertEquals(record().identifier, loaded.identifier)
        assertEquals(record().refreshToken, loaded.refreshToken)
        assertEquals(record().sessionId, loaded.sessionId)
        store().clear()
        assertNull(store().load())
    }

    @Test
    fun wrappingKey_isNonExportable() {
        store().save(record())
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        assertTrue(keystore.containsAlias(AndroidKeystoreKeyProvider.KEY_ALIAS))
        assertNull(keystore.getKey(AndroidKeystoreKeyProvider.KEY_ALIAS, null).encoded)
        store().clear()
    }

    @Test
    fun corruptFile_failsClosed() {
        store().save(record())
        val file = FileSessionStore.rawFile(context)
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
        file.writeBytes(bytes)
        assertThrows(SessionStoreException::class.java) {
            store().load()
        }
        store().clear()
    }

    @Test
    fun storedFile_containsNoPlaintext() {
        store().save(record())
        val stored = FileSessionStore.rawFile(context).readBytes()
        val text = String(stored, Charsets.UTF_8)
        assertFalse(text.contains("refresh-instrumented-token"))
        // Envelope structure inspectable without plaintext.
        assertEquals(0x53.toByte(), stored[0])
        assertEquals(0x56.toByte(), stored[1])
        assertEquals(0x4C.toByte(), stored[2])
        assertEquals(0x54.toByte(), stored[3])
        store().clear()
    }

    @Test
    fun sessionFile_livesOutsideCryptoVault() {
        store().save(record())
        val sessionFile = FileSessionStore.rawFile(context)
        assertTrue(sessionFile.isFile)
        // Namespace separation: no session bytes inside the crypto vault dir.
        val vaultDir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val vaultFiles = vaultDir.listFiles()?.filter { it.isFile }.orEmpty()
        assertTrue(vaultFiles.none { it.name == sessionFile.name })
        assertTrue(vaultFiles.none { it.readBytes().contentEquals(sessionFile.readBytes()) })
        store().clear()
    }
}
