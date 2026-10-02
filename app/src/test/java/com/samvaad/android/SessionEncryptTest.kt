package com.samvaad.android

import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Production encryption-seam tests through REAL native libsignal 0.86.5
 * (host JVM leg). No network, no files, no UI.
 *
 * Every assertion reads the ACTUAL `CiphertextMessage.getType()` off the
 * wire object via [AndroidSignalAdapter.envelopeTypeFor] — the
 * PREKEY_INIT results below are observed behavior, never assumptions.
 */
class SessionEncryptTest {

    private val plaintext = "samvaad-slice7-test-message".toByteArray(Charsets.UTF_8)

    private data class Fixture(
        val adapter: AndroidSignalAdapter,
        val local: com.samvaad.android.crypto.SpikeCryptoMaterial.Identity,
        val localRegId: Int,
        val remoteUsername: String,
        val remoteSignalDeviceId: Int,
        val sessionBytes: ByteArray,
        val remoteIdentity: ByteArray,
    )

    private fun established(
        withOtk: Boolean = true,
        username: String = "bob",
        signalDeviceId: Int = 2,
        localRegId: Int = 4242,
        remoteRegId: Int = 7001,
    ): Fixture {
        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        val peer = AndroidSignalAdapter()
        val pid = peer.generateIdentity()
        val spk = peer.generateSignedPrekey(pid, 11)
        val kyb = peer.generateKyberPrekey(pid, 21)
        val otk = peer.generateOneTimePrekey(101)
        val established = adapter.establishOutboundSession(
            local, localRegId, username,
            RemotePrekeyBundle(
                remoteRegId, signalDeviceId, pid.publicKey,
                spk.prekeyId, spk.publicKey, spk.signature,
                if (withOtk) otk.prekeyId else null,
                if (withOtk) otk.publicKey else null,
                kyb.prekeyId, kyb.publicKey, kyb.signature,
            ),
        )
        return Fixture(
            adapter, local, localRegId, username, signalDeviceId,
            established.sessionBytes, established.remoteIdentityBytes,
        )
    }

    private fun encrypt(f: Fixture, bytes: ByteArray, text: ByteArray = plaintext) =
        f.adapter.encryptForSubmit(
            f.local, f.localRegId, bytes, f.remoteIdentity,
            f.remoteUsername, f.remoteSignalDeviceId, text,
        )

    @Test
    fun establishedSession_encryptsToNonEmptyPrekeyInit() {
        val f = established()
        val out = encrypt(f, f.sessionBytes)
        assertTrue(out.ciphertextBytes.isNotEmpty())
        // Observed wire type, translated — not assumed.
        assertEquals(AndroidSignalAdapter.ENVELOPE_PREKEY_INIT, out.envelopeType)
        assertEquals("PREKEY_INIT", out.envelopeType)
        assertTrue(out.postEncryptSessionBytes.isNotEmpty())
        // Ciphertext is bounded by the server transport bound.
        assertTrue(out.ciphertextBytes.size <= 65_536)
    }

    @Test
    fun envelopeTypeFor_translatesBothKnownTypes() {
        val adapter = AndroidSignalAdapter()
        assertEquals("PREKEY_INIT", adapter.envelopeTypeFor(AndroidSignalAdapter.PREKEY_TYPE))
        assertEquals("PREKEY_INIT", adapter.envelopeTypeFor(3))
        assertEquals("RATCHET", adapter.envelopeTypeFor(AndroidSignalAdapter.WHISPER_TYPE))
        assertEquals("RATCHET", adapter.envelopeTypeFor(2))
    }

    @Test
    fun envelopeTypeFor_unknownType_failsClosed() {
        val adapter = AndroidSignalAdapter()
        assertThrows(SessionCryptoException.EstablishmentFailed::class.java) {
            adapter.envelopeTypeFor(7)
        }
        assertThrows(SessionCryptoException.EstablishmentFailed::class.java) {
            adapter.envelopeTypeFor(0)
        }
        assertThrows(SessionCryptoException.EstablishmentFailed::class.java) {
            adapter.envelopeTypeFor(8)
        }
    }

    @Test
    fun secondOutboundEncryption_differsButStaysPrekeyInit() {
        val f = established()
        val first = encrypt(f, f.sessionBytes)
        // Ratchet advanced: re-seal semantics proven by feeding the
        // post-encrypt bytes back as the next load state.
        val second = encrypt(f, first.postEncryptSessionBytes)
        assertFalse(first.ciphertextBytes.contentEquals(second.ciphertextBytes))
        // No inbound reply was ever decrypted: still unacknowledged.
        assertEquals("PREKEY_INIT", second.envelopeType)
    }

    @Test
    fun postEncryptSessionBytes_differAndRemainUsable() {
        val f = established()
        val first = encrypt(f, f.sessionBytes)
        assertFalse(first.postEncryptSessionBytes.contentEquals(f.sessionBytes))
        // The advanced state restores with a live sender chain.
        val info = f.adapter.inspectSession(first.postEncryptSessionBytes)
        assertArrayEquals(f.remoteIdentity, info.remoteIdentityBytes)
        // …and encrypts again (ratchet continuity without re-establishment).
        val second = encrypt(f, first.postEncryptSessionBytes)
        assertTrue(second.ciphertextBytes.isNotEmpty())
    }

    @Test
    fun identityPinning_stillEnforcedOnEncrypt() {
        val f = established()
        val other = established(username = "mallory")
        assertThrows(SessionCryptoException.UntrustedIdentity::class.java) {
            f.adapter.encryptForSubmit(
                f.local, f.localRegId, f.sessionBytes, other.remoteIdentity,
                f.remoteUsername, f.remoteSignalDeviceId, plaintext,
            )
        }
    }

    @Test
    fun encrypt_withoutSession_failsClosed() {
        val f = established()
        // Empty-but-valid record: no sender chain, no session.
        val empty = org.signal.libsignal.protocol.state.SessionRecord().serialize()
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            encrypt(f, empty)
        }
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            encrypt(f, ByteArray(24) { 0x02 })
        }
    }

    @Test
    fun encrypt_emptyPlaintext_rejectedBeforeCrypto() {
        val f = established()
        assertThrows(IllegalArgumentException::class.java) {
            encrypt(f, f.sessionBytes, ByteArray(0))
        }
    }

    @Test
    fun encrypt_fallbackSession_producesPrekeyInit() {
        val f = established(withOtk = false)
        val out = encrypt(f, f.sessionBytes)
        assertEquals("PREKEY_INIT", out.envelopeType)
        assertTrue(out.ciphertextBytes.isNotEmpty())
    }
}
