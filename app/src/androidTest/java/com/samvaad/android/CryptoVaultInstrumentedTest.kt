package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import java.io.File
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Vault slice instrumented tests: real Android Keystore custody on this
 * device's ABI (`libsignal-android:0.86.5` natives + system Keystore).
 *
 * Full cycle per test: generate → export → seal → drop ALL instances →
 * new instances → unseal → restore → libsignal re-verify. No network,
 * no UI, no enrollment; assertions compare booleans/lengths only and
 * never log key material.
 */
@RunWith(AndroidJUnit4::class)
class CryptoVaultInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun vault(alias: String = AndroidKeystoreKeyProvider.KEY_ALIAS) =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider(alias))

    @Test
    fun vault_keystoreRoundTrip_recoversIdenticalIdentity() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 2201)
        val kyber = adapter.generateKyberPrekey(identity, 4401)
        val otpks = (1..5).map { adapter.generateOneTimePrekey(5000 + it) }
        val v = vault()
        v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        v.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        v.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            v.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }

        // Prove storage location: no-backup dir (never cloud/D2D backed up).
        val dir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        assertTrue(dir.isDirectory)
        assertEquals(8, dir.listFiles()!!.count { it.isFile })

        // Drop everything: simulate process death (memory only; files+Keystore persist).
        val freshVault = vault()
        val freshAdapter = AndroidSignalAdapter()

        val idBack = freshAdapter.restoreRecord(
            identity.privateHandle,
            freshVault.unseal(identity.privateHandle, CryptoRecordKind.IDENTITY),
        ) as AndroidSignalAdapter.RestoredPublic.Identity
        assertArrayEquals(identity.publicKey, idBack.value.publicKey)

        val signedBack = freshAdapter.restoreRecord(
            signed.privateHandle,
            freshVault.unseal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY),
        ) as AndroidSignalAdapter.RestoredPublic.Signed
        assertArrayEquals(signed.publicKey, signedBack.value.publicKey)
        assertTrue(
            freshAdapter.verifySignedPrekey(
                idBack.value.publicKey, signedBack.value.publicKey, signedBack.value.signature
            )
        )

        val kyberBack = freshAdapter.restoreRecord(
            kyber.privateHandle,
            freshVault.unseal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY),
        ) as AndroidSignalAdapter.RestoredPublic.Kyber
        assertTrue(
            freshAdapter.verifyKyberSignature(
                idBack.value.publicKey, kyberBack.value.publicKey, kyberBack.value.signature
            )
        )

        otpks.forEach {
            val back = freshAdapter.restoreRecord(
                it.privateHandle,
                freshVault.unseal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY),
            ) as AndroidSignalAdapter.RestoredPublic.OneTime
            assertArrayEquals(it.publicKey, back.value.publicKey)
            assertTrue(freshAdapter.parseEcPublic(back.value.publicKey))
        }

        // Cleanup: leave no test records behind.
        (listOf(
            identity.privateHandle to CryptoRecordKind.IDENTITY,
            signed.privateHandle to CryptoRecordKind.SIGNED_PREKEY,
            kyber.privateHandle to CryptoRecordKind.KYBER_PREKEY,
        ) + otpks.map { it.privateHandle to CryptoRecordKind.ONE_TIME_PREKEY })
            .forEach { (h, k) -> freshVault.delete(h, k) }
    }

    @Test
    fun vault_wrappingKey_isNonExportable() {
        vault().let { v ->
            val adapter = AndroidSignalAdapter()
            val identity = adapter.generateIdentity()
            v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
            v.delete(identity.privateHandle, CryptoRecordKind.IDENTITY)
        }
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        assertTrue(store.containsAlias(AndroidKeystoreKeyProvider.KEY_ALIAS))
        val key = store.getKey(AndroidKeystoreKeyProvider.KEY_ALIAS, null)
        // Non-exportable proof: Keystore refuses to reveal key bytes.
        assertTrue(key.encoded == null)
    }

    @Test
    fun vault_missingAlias_failsClosedWithoutCreatingKey() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        vault().seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))

        val absentAlias = "samvaad-test-absent-alias"
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        assertFalse(store.containsAlias(absentAlias))

        val orphanVault = vault(absentAlias)
        assertThrows(VaultException.WrappingKeyMissing::class.java) {
            orphanVault.unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        }
        // Fail-closed proof: no replacement key was minted.
        store.load(null)
        assertFalse(store.containsAlias(absentAlias))

        vault().delete(identity.privateHandle, CryptoRecordKind.IDENTITY)
    }

    @Test
    fun vault_corruptFile_failsClosed() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val v = vault()
        v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))

        val dir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val file = dir.listFiles()!!.first { it.isFile && it.name.contains(identity.privateHandle.id.toString()) }
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
        file.writeBytes(bytes)

        assertThrows(VaultException::class.java) {
            vault().unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        }
        // No silent regeneration: the stored file is still the (corrupt)
        // original; nothing was overwritten with fresh material.
        assertEquals(bytes.size, file.readBytes().size)
        v.delete(identity.privateHandle, CryptoRecordKind.IDENTITY)
    }

    @Test
    fun vault_storedFiles_containNoPlaintext() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val recordCopy = adapter.exportRecord(identity.privateHandle).copyOf()
        vault().seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))

        val dir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val file = dir.listFiles()!!.first { it.isFile && it.name.contains(identity.privateHandle.id.toString()) }
        val stored = file.readBytes()
        assertFalse(containsSubsequence(stored, recordCopy))
        assertFalse(containsSubsequence(stored, identity.publicKey))
        // Envelope structure is inspectable without plaintext: magic + version.
        assertEquals(0x53.toByte(), stored[0])
        assertEquals(0x56.toByte(), stored[1])
        assertEquals(0x4C.toByte(), stored[2])
        assertEquals(0x54.toByte(), stored[3])

        vault().delete(identity.privateHandle, CryptoRecordKind.IDENTITY)
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
