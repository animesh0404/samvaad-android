package com.samvaad.android

import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Inbound decryption tests through REAL native libsignal 0.86.5 (host
 * JVM leg). No network, no files, no UI.
 *
 * Two adapter instances play the two devices with correct protocol
 * direction throughout: Alice establishes outbound to Bob and encrypts;
 * Bob decrypts with his full private material (identity/signed/kyber/
 * OTPKs live in his adapter, exactly as restored from the vault in
 * production). Bob's pinned identity for Alice is Alice's public key.
 * Every assertion observes real libsignal behavior.
 */
class SessionDecryptTest {

    private val plaintext = "slice8-inbox-plaintext".toByteArray(Charsets.UTF_8)

    private data class BobKeys(
        val adapter: AndroidSignalAdapter,
        val identity: SpikeCryptoMaterial.Identity,
        val registrationId: Int,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private data class AliceKeys(
        val adapter: AndroidSignalAdapter,
        val identity: SpikeCryptoMaterial.Identity,
        val registrationId: Int,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private fun freshBob(
        regId: Int = 7001,
        otkIds: List<Int> = listOf(101, 102, 103),
    ): BobKeys {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return BobKeys(
            adapter, identity, regId,
            adapter.generateSignedPrekey(identity, 11),
            adapter.generateKyberPrekey(identity, 21),
            otkIds.map { adapter.generateOneTimePrekey(it) },
        )
    }

    private fun freshAlice(regId: Int = 4242): AliceKeys {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return AliceKeys(
            adapter, identity, regId,
            adapter.generateSignedPrekey(identity, 31),
            adapter.generateKyberPrekey(identity, 41),
            listOf(adapter.generateOneTimePrekey(301)),
        )
    }

    private fun bobBundle(bob: BobKeys, signalDeviceId: Int = 2, otkIndex: Int = 0) =
        RemotePrekeyBundle(
            registrationId = bob.registrationId,
            signalDeviceId = signalDeviceId,
            identityKey = bob.identity.publicKey,
            signedPrekeyId = bob.signed.prekeyId,
            signedPrekey = bob.signed.publicKey,
            signedPrekeySignature = bob.signed.signature,
            oneTimePrekeyId = bob.otpks[otkIndex].prekeyId,
            oneTimePrekey = bob.otpks[otkIndex].publicKey,
            kyberPrekeyId = bob.kyber.prekeyId,
            kyberPrekey = bob.kyber.publicKey,
            kyberPrekeySignature = bob.kyber.signature,
        )

    /** Alice establishes outbound to Bob; returns her advanced session + wire. */
    private data class AliceCiphertext(
        val sessionBytes: ByteArray,
        val ciphertext: ByteArray,
        val envelopeType: String,
    )

    private fun aliceEncrypts(
        alice: AliceKeys,
        bob: BobKeys,
        text: ByteArray = plaintext,
        otkIndex: Int = 0,
    ): AliceCiphertext {
        val established = alice.adapter.establishOutboundSession(
            alice.identity, alice.registrationId, "bob", bobBundle(bob, otkIndex = otkIndex)
        )
        val encrypted = alice.adapter.encryptForSubmit(
            alice.identity, alice.registrationId,
            established.sessionBytes, bob.identity.publicKey,
            "bob", 2, text,
        )
        return AliceCiphertext(
            encrypted.postEncryptSessionBytes, encrypted.ciphertextBytes, encrypted.envelopeType
        )
    }

    private fun bobDecrypts(
        bob: BobKeys,
        alice: AliceKeys,
        sessionBytes: ByteArray,
        envelopeType: String,
        ciphertext: ByteArray,
    ) = bob.adapter.decryptForInbox(
        localIdentity = bob.identity,
        localRegistrationId = bob.registrationId,
        signed = bob.signed,
        kyber = bob.kyber,
        otpks = bob.otpks,
        sessionBytes = sessionBytes,
        pinnedRemoteIdentity = alice.identity.publicKey,
        remoteUsername = "alice",
        remoteSignalDeviceId = 1,
        envelopeType = envelopeType,
        ciphertext = ciphertext,
    )

    private fun aliceDecrypts(
        alice: AliceKeys,
        bob: BobKeys,
        sessionBytes: ByteArray,
        envelopeType: String,
        ciphertext: ByteArray,
    ) = alice.adapter.decryptForInbox(
        localIdentity = alice.identity,
        localRegistrationId = alice.registrationId,
        signed = alice.signed,
        kyber = alice.kyber,
        otpks = alice.otpks,
        sessionBytes = sessionBytes,
        pinnedRemoteIdentity = bob.identity.publicKey,
        remoteUsername = "bob",
        remoteSignalDeviceId = 2,
        envelopeType = envelopeType,
        ciphertext = ciphertext,
    )

    private fun emptySession(): ByteArray =
        org.signal.libsignal.protocol.state.SessionRecord().serialize()

    @Test
    fun prekeyDecrypt_recoversExactPlaintext_mutatesSession() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        assertEquals("PREKEY_INIT", wire.envelopeType)
        val out = bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        assertArrayEquals(plaintext, out.plaintext)
        assertArrayEquals(alice.identity.publicKey, out.remoteIdentityBytes)
        assertTrue(out.postDecryptSessionBytes.isNotEmpty())
        assertFalse(emptySession().contentEquals(out.postDecryptSessionBytes))
        // Restored post-decrypt state is usable (readiness gate passes).
        val info = bob.adapter.inspectSession(out.postDecryptSessionBytes)
        assertArrayEquals(alice.identity.publicKey, info.remoteIdentityBytes)
    }

    @Test
    fun prekeyDecrypt_installsSenderChain_nextEncryptIsRatchet() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        val first = bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        // Bob can now encrypt back, and the acknowledged session speaks RATCHET.
        val reply = bob.adapter.encryptForSubmit(
            bob.identity, bob.registrationId,
            first.postDecryptSessionBytes, alice.identity.publicKey,
            "alice", 1, plaintext,
        )
        assertEquals("RATCHET", reply.envelopeType)
        // …which Alice decrypts through the RATCHET path against her session.
        val back = aliceDecrypts(alice, bob, wire.sessionBytes, "RATCHET", reply.ciphertextBytes)
        assertArrayEquals(plaintext, back.plaintext)
    }

    @Test
    fun secondRatchetDecrypt_succeedsAfterPrekey() {
        val bob = freshBob()
        val alice = freshAlice()
        // Full ping-pong: Alice PREKEY → Bob decrypts → Bob replies RATCHET.
        val wire = aliceEncrypts(alice, bob)
        val first = bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        val reply = bob.adapter.encryptForSubmit(
            bob.identity, bob.registrationId, first.postDecryptSessionBytes,
            alice.identity.publicKey, "alice", 1, plaintext,
        )
        assertEquals("RATCHET", reply.envelopeType)
        // Alice archives no prior inbound state here: her session (from her
        // own establish+encrypt) decrypts Bob's RATCHET reply directly.
        val out = aliceDecrypts(alice, bob, wire.sessionBytes, "RATCHET", reply.ciphertextBytes)
        assertArrayEquals(plaintext, out.plaintext)
        assertFalse(wire.sessionBytes.contentEquals(out.postDecryptSessionBytes))
    }

    @Test
    fun pinnedIdentity_enforced_wrongIdentityRejected() {
        val bob = freshBob()
        val alice = freshAlice()
        val other = freshAlice(regId = 5555)
        val wire = aliceEncrypts(alice, bob)
        val empty = emptySession()
        // Wrong but well-formed pin: distrusted.
        assertThrows(SessionCryptoException.UntrustedIdentity::class.java) {
            bob.adapter.decryptForInbox(
                bob.identity, bob.registrationId, bob.signed, bob.kyber, bob.otpks,
                empty, other.identity.publicKey, "alice", 1, "PREKEY_INIT", wire.ciphertext,
            )
        }
        // Garbage pin: invalid bundle.
        assertThrows(SessionCryptoException.InvalidBundle::class.java) {
            bob.adapter.decryptForInbox(
                bob.identity, bob.registrationId, bob.signed, bob.kyber, bob.otpks,
                empty, ByteArray(33) { 0x07 }, "alice", 1, "PREKEY_INIT", wire.ciphertext,
            )
        }
    }

    @Test
    fun malformedCiphertext_rejected() {
        val bob = freshBob()
        val alice = freshAlice()
        val empty = emptySession()
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            bobDecrypts(bob, alice, empty, "PREKEY_INIT", ByteArray(32) { 0x01 })
        }
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            bobDecrypts(bob, alice, empty, "RATCHET", ByteArray(32) { 0x01 })
        }
    }

    @Test
    fun unsupportedEnvelopeType_rejectedBeforeCrypto() {
        val bob = freshBob()
        val alice = freshAlice()
        val empty = emptySession()
        assertThrows(SessionCryptoException.InvalidBundle::class.java) {
            bobDecrypts(bob, alice, empty, "SENDERKEY", plaintext)
        }
        assertThrows(SessionCryptoException.InvalidBundle::class.java) {
            bobDecrypts(bob, alice, empty, "", plaintext)
        }
    }

    @Test
    fun missingSession_whisperRejected() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        // Empty-but-valid record: no session for this peer on RATCHET path.
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            bobDecrypts(bob, alice, emptySession(), "RATCHET", wire.ciphertext)
        }
    }

    @Test
    fun unknownOtkId_rejected() {
        val bob = freshBob(otkIds = listOf(101, 102))
        val alice = freshAlice()
        // Alice's bundle advertises OTK 999, which Bob never held. Her
        // side still establishes (OTKs carry no signature to check)…
        val foreignOtk = alice.adapter.generateOneTimePrekey(999)
        val established = alice.adapter.establishOutboundSession(
            alice.identity, alice.registrationId, "bob",
            bobBundle(bob).copy(oneTimePrekeyId = 999, oneTimePrekey = foreignOtk.publicKey),
        )
        val encrypted = alice.adapter.encryptForSubmit(
            alice.identity, alice.registrationId,
            established.sessionBytes, bob.identity.publicKey,
            "bob", 2, plaintext,
        )
        // …but Bob's store has no private half for id 999.
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", encrypted.ciphertextBytes)
        }
    }

    @Test
    fun duplicatePrekey_throwsWithoutMutation() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        val first = bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        // Simulate the persistence boundary: restore S1, redeliver C1.
        assertThrows(SessionCryptoException.DuplicateMessage::class.java) {
            bobDecrypts(bob, alice, first.postDecryptSessionBytes, "PREKEY_INIT", wire.ciphertext)
        }
        // The store still advances fresh traffic afterwards (no corruption).
        val wire2 = aliceEncrypts(alice, bob, otkIndex = 1)
        val second = bobDecrypts(
            bob, alice, first.postDecryptSessionBytes, "PREKEY_INIT", wire2.ciphertext
        )
        assertArrayEquals(plaintext, second.plaintext)
    }

    @Test
    fun duplicateRatchet_throwsWithoutMutation() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        val first = bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        val reply = bob.adapter.encryptForSubmit(
            bob.identity, bob.registrationId, first.postDecryptSessionBytes,
            alice.identity.publicKey, "alice", 1, plaintext,
        )
        assertEquals("RATCHET", reply.envelopeType)
        val out = aliceDecrypts(alice, bob, wire.sessionBytes, "RATCHET", reply.ciphertextBytes)
        // Exact same RATCHET ciphertext against restored post-decrypt state.
        assertThrows(SessionCryptoException.DuplicateMessage::class.java) {
            aliceDecrypts(alice, bob, out.postDecryptSessionBytes, "RATCHET", reply.ciphertextBytes)
        }
        // Fresh traffic still flows afterwards.
        val reply2 = bob.adapter.encryptForSubmit(
            bob.identity, bob.registrationId, reply.postEncryptSessionBytes,
            alice.identity.publicKey, "alice", 1, plaintext,
        )
        val out2 = aliceDecrypts(
            alice, bob, out.postDecryptSessionBytes, "RATCHET", reply2.ciphertextBytes
        )
        assertArrayEquals(plaintext, out2.plaintext)
    }

    @Test
    fun kyberReplay_failsClosed() {
        val bob = freshBob()
        val alice = freshAlice()
        val wire = aliceEncrypts(alice, bob)
        bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        // Reset to pre-decrypt session state (as if persistence were lost)
        // and feed the same PREKEY again: the Kyber base key was already
        // consumed, so replay protection must fire instead of success.
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            bobDecrypts(bob, alice, emptySession(), "PREKEY_INIT", wire.ciphertext)
        }
    }
}
