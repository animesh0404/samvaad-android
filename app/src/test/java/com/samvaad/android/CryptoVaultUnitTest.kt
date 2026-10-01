package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.RecordEnvelopeCodec
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.crypto.WrappingKeyProvider
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Vault slice unit tests: envelope codec, AAD binding, fail-closed
 * handling, file durability, and no-plaintext storage.
 *
 * The wrapping key here is an ephemeral in-memory AES key (test-only stand
 * in for the Keystore key — same AES-GCM algorithm, no key custody under
 * test). Keystore custody itself is covered by instrumented tests. No
 * network, no UI, no enrollment. Test-only IDs carry no production meaning.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class CryptoVaultUnitTest {

    /** Test-only key custody: standard AES-GCM key, never persisted. */
    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        var creations = 0
            private set

        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k; creations++ }
            }

        override fun getExisting(): SecretKey? = key

        fun dropKey() {
            key = null
        }
    }

    private lateinit var context: Context
    private lateinit var keys: EphemeralKeys

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keys = EphemeralKeys()
        // Isolate each test: fresh vault directory under a unique parent.
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
            .deleteRecursively()
    }

    private fun vault(): AndroidCryptoVault = AndroidCryptoVault(context, keys)

    private fun freshInstance(): AndroidCryptoVault =
        AndroidCryptoVault(context, keys)

    @Test
    fun envelope_roundTrip() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val handle = identity.privateHandle
        val record = adapter.exportRecord(handle)

        vault().seal(handle, handle.kind, record)
        val recovered = freshInstance().unseal(handle, handle.kind)

        val restored = AndroidSignalAdapter().restoreRecord(handle, recovered)
            as AndroidSignalAdapter.RestoredPublic.Identity
        assertArrayEquals(identity.publicKey, restored.value.publicKey)
    }

    @Test
    fun multipleRecords_coexistAndStayIsolated() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 2201)
        val kyber = adapter.generateKyberPrekey(identity, 4401)
        val v = vault()

        v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        v.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        v.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))

        assertTrue(v.exists(identity.privateHandle, CryptoRecordKind.IDENTITY))
        assertTrue(v.exists(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY))
        assertTrue(v.exists(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY))

        // Deleting one leaves the others intact and recoverable.
        v.delete(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY)
        assertFalse(v.exists(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY))
        val fresh = AndroidSignalAdapter()
        val idBack = fresh.restoreRecord(
            identity.privateHandle, freshInstance().unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        ) as AndroidSignalAdapter.RestoredPublic.Identity
        assertArrayEquals(identity.publicKey, idBack.value.publicKey)
        assertThrows(VaultException.RecordMissing::class.java) {
            freshInstance().unseal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY)
        }
    }

    @Test
    fun aad_bindsUuid() {
        val key = keys.getOrCreate()
        val idA = SealedHandle(CryptoRecordKind.IDENTITY)
        val idB = SealedHandle(CryptoRecordKind.IDENTITY)
        val envelope = RecordEnvelopeCodec.seal(key, CryptoRecordKind.IDENTITY, idA.id, byteArrayOf(1, 2, 3))
        assertThrows(VaultException.HandleMismatch::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.IDENTITY, idB.id, envelope)
        }
    }

    @Test
    fun aad_bindsRecordKind() {
        val key = keys.getOrCreate()
        val id = UUID.randomUUID()
        val envelope = RecordEnvelopeCodec.seal(key, CryptoRecordKind.IDENTITY, id, byteArrayOf(1, 2, 3))
        assertThrows(VaultException.HandleMismatch::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.SIGNED_PREKEY, id, envelope)
        }
        // Genuine AAD proof: flip the header kind byte AND request the
        // flipped kind, so the structural check passes and only GCM AAD
        // (bound at seal time to IDENTITY) can refuse.
        val retagged = envelope.copyOf().also { it[5] = CryptoRecordKind.KYBER_PREKEY.code }
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.KYBER_PREKEY, id, retagged)
        }
    }

    @Test
    fun unknownSchemaVersion_rejected() {
        val key = keys.getOrCreate()
        val id = UUID.randomUUID()
        val envelope = RecordEnvelopeCodec.seal(key, CryptoRecordKind.IDENTITY, id, byteArrayOf(1, 2, 3))
        // Version byte sits at offset 4 ("SVLT" magic).
        val tampered = envelope.copyOf().also { it[4] = 0x7F }
        val parsed = RecordEnvelopeCodec.parse(tampered)
        assertEquals(0x7F, parsed.version)
        assertThrows(VaultException.UnknownVersion::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.IDENTITY, id, tampered)
        }
    }

    @Test
    fun corruptedCiphertext_rejected() {
        val key = keys.getOrCreate()
        val id = UUID.randomUUID()
        val envelope = RecordEnvelopeCodec.seal(key, CryptoRecordKind.IDENTITY, id, ByteArray(64) { 0x5A })
        val tampered = envelope.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.IDENTITY, id, tampered)
        }
    }

    @Test
    fun truncatedEnvelope_rejected() {
        val key = keys.getOrCreate()
        val id = UUID.randomUUID()
        val envelope = RecordEnvelopeCodec.seal(key, CryptoRecordKind.IDENTITY, id, ByteArray(32))
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.IDENTITY, id, envelope.copyOf(10))
        }
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            RecordEnvelopeCodec.unseal(key, CryptoRecordKind.IDENTITY, id, ByteArray(0))
        }
    }

    @Test
    fun wrongUuid_rejected() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        vault().seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        // File-layer isolation: filenames embed the UUID, so an unknown
        // UUID addresses no record at all. Envelope-level UUID binding
        // (AAD) is proven at the codec layer by aad_bindsUuid.
        val impostor = SealedHandle(CryptoRecordKind.IDENTITY)
        assertThrows(VaultException.RecordMissing::class.java) {
            freshInstance().unseal(impostor, CryptoRecordKind.IDENTITY)
        }
        assertFalse(freshInstance().exists(impostor, CryptoRecordKind.IDENTITY))
        // The victim remains intact and recoverable.
        val fresh = AndroidSignalAdapter()
        val back = fresh.restoreRecord(
            identity.privateHandle, freshInstance().unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        ) as AndroidSignalAdapter.RestoredPublic.Identity
        assertArrayEquals(identity.publicKey, back.value.publicKey)
    }

    @Test
    fun wrongKind_rejected() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        vault().seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        // API-level guard: handle kind must match the requested kind.
        assertThrows(IllegalArgumentException::class.java) {
            freshInstance().unseal(identity.privateHandle, CryptoRecordKind.SIGNED_PREKEY)
        }
        // On-disk kind binding: the filename and the envelope header both
        // carry the kind. Flipping the header's kind byte is caught by the
        // structural handle check before decryption (fail closed either
        // way); GCM-level kind binding is proven at the codec layer by
        // aad_bindsRecordKind.
        val dir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val file = dir.listFiles()!!.first { it.isFile }
        val tampered = file.readBytes().also {
            // Kind byte sits at offset 5 ("SVLT" + version).
            it[5] = CryptoRecordKind.KYBER_PREKEY.code
        }
        file.writeBytes(tampered)
        assertThrows(VaultException.HandleMismatch::class.java) {
            freshInstance().unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        }
    }

    @Test
    fun missingFile_rejectedAsMissing() {
        val handle = SealedHandle(CryptoRecordKind.IDENTITY)
        assertThrows(VaultException.RecordMissing::class.java) {
            vault().unseal(handle, CryptoRecordKind.IDENTITY)
        }
        assertFalse(vault().exists(handle, CryptoRecordKind.IDENTITY))
    }

    @Test
    fun missingKey_failsClosedWithoutRecreating() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        vault().seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        val creationsBefore = keys.creations
        keys.dropKey()
        assertThrows(VaultException.WrappingKeyMissing::class.java) {
            freshInstance().unseal(identity.privateHandle, CryptoRecordKind.IDENTITY)
        }
        // Fail-closed proof: unseal must not mint a replacement key.
        assertEquals(creationsBefore, keys.creations)
        assertTrue(keys.getExisting() == null)
    }

    @Test
    fun storedFiles_containNoPlaintext() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 2201)
        val record = adapter.exportRecord(identity.privateHandle)
        val recordCopy = record.copyOf()
        val signedRecord = adapter.exportRecord(signed.privateHandle)
        val signedCopy = signedRecord.copyOf()
        val v = vault()
        v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, record)
        v.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, signedRecord)

        val dir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val files = dir.listFiles()!!.filter { it.isFile }
        assertEquals(2, files.size)
        for (f in files) {
            val bytes = f.readBytes()
            assertFalse(containsSubsequence(bytes, recordCopy))
            assertFalse(containsSubsequence(bytes, signedCopy))
            assertFalse(containsSubsequence(bytes, identity.publicKey))
            assertFalse(containsSubsequence(bytes, signed.publicKey))
        }
    }

    @Test
    fun garbageBytes_failLibsignalReconstruction() {
        val handle = SealedHandle(CryptoRecordKind.IDENTITY)
        assertThrows(Exception::class.java) {
            AndroidSignalAdapter().restoreRecord(handle, ByteArray(64) { 0x11 })
        }
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
