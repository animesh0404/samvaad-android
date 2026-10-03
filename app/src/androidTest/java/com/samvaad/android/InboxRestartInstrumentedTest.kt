package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SignalSessionEntry
import java.io.File
import java.util.Base64
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device inbox continuity: REAL libsignal natives (device ABI) + REAL
 * Keystore wrapping key + REAL vault files. No network, no TLS, no UI.
 *
 * A full ping-pong across process death, driven from the host:
 *
 * 1. `sealPhase` — Alice sends PREKEY#1, Bob decrypts + seals, Bob
 *    replies RATCHET (sender chain installed by the PREKEY decrypt).
 *    Phase file carries ONLY non-secret identifiers plus test
 *    ciphertext (never plaintext, never private material).
 * 2. Host runs `adb shell am force-stop com.samvaad.android` (and
 *    optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process: Alice restores and decrypts Bob's
 *    reply, Alice answers RATCHET#2, Bob restores and decrypts it, and
 *    the old PREKEY#1 still resolves as a duplicate (the ACK path stays
 *    valid after restart).
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 */
@RunWith(AndroidJUnit4::class)
class InboxRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun cryptoVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider())

    private fun sessionVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider(), FileSessionMetadataStore.SUBDIR)

    private fun phaseFile(): File = File(context.cacheDir, "inbox-restart-phase.txt")

    private val aliceDeviceId = "22222222-2222-3333-4444-555555555555"
    private val bobDeviceId = "11111111-1111-1111-1111-111111111111"
    private val plaintext = "slice8-inbox-plaintext".toByteArray(Charsets.UTF_8)

    private data class Side(
        val adapter: AndroidSignalAdapter,
        val identity: SpikeCryptoMaterial.Identity,
        val regId: Int,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private fun freshSide(
        adapter: AndroidSignalAdapter,
        regId: Int,
        signedId: Int,
        kyberId: Int,
        otkId: Int,
    ): Side {
        val identity = adapter.generateIdentity()
        return Side(
            adapter, identity, regId,
            adapter.generateSignedPrekey(identity, signedId),
            adapter.generateKyberPrekey(identity, kyberId),
            listOf(adapter.generateOneTimePrekey(otkId)),
        )
    }

    private fun sealSide(vault: AndroidCryptoVault, side: Side) {
        vault.seal(
            side.identity.privateHandle, CryptoRecordKind.IDENTITY,
            side.adapter.exportRecord(side.identity.privateHandle),
        )
        vault.seal(
            side.signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY,
            side.adapter.exportRecord(side.signed.privateHandle),
        )
        vault.seal(
            side.kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY,
            side.adapter.exportRecord(side.kyber.privateHandle),
        )
        side.otpks.forEach {
            vault.seal(
                it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY,
                side.adapter.exportRecord(it.privateHandle),
            )
        }
    }

    private fun bundleOf(
        regId: Int,
        signalDeviceId: Int,
        identity: ByteArray,
        signedId: Int,
        signed: ByteArray,
        signedSig: ByteArray,
        otkId: Int,
        otk: ByteArray,
        kyberId: Int,
        kyber: ByteArray,
        kyberSig: ByteArray,
    ) = RemotePrekeyBundle(
        registrationId = regId,
        signalDeviceId = signalDeviceId,
        identityKey = identity,
        signedPrekeyId = signedId,
        signedPrekey = signed,
        signedPrekeySignature = signedSig,
        oneTimePrekeyId = otkId,
        oneTimePrekey = otk,
        kyberPrekeyId = kyberId,
        kyberPrekey = kyber,
        kyberPrekeySignature = kyberSig,
    )

    private fun sessionHandleIn(uuid: String, kind: CryptoRecordKind) =
        SpikeCryptoMaterial.SealedHandle(UUID.fromString(uuid), kind)

    @Test
    fun sealPhase() {
        phaseFile().delete()
        FileSessionMetadataStore(context).remove(aliceDeviceId)

        val aliceAdapter = AndroidSignalAdapter()
        val alice = freshSide(aliceAdapter, 4242, 31, 41, 301)
        val bobAdapter = AndroidSignalAdapter()
        val bob = freshSide(bobAdapter, 7001, 11, 21, 101)
        sealSide(cryptoVault(), alice)
        sealSide(cryptoVault(), bob)

        // Alice → Bob PREKEY#1 through the production outbound seam.
        val established = aliceAdapter.establishOutboundSession(
            alice.identity, alice.regId, "bob",
            bundleOf(
                bob.regId, 1, bob.identity.publicKey,
                bob.signed.prekeyId, bob.signed.publicKey, bob.signed.signature,
                bob.otpks.single().prekeyId, bob.otpks.single().publicKey,
                bob.kyber.prekeyId, bob.kyber.publicKey, bob.kyber.signature,
            ),
        )
        val first = aliceAdapter.encryptForSubmit(
            alice.identity, alice.regId,
            established.sessionBytes, bob.identity.publicKey,
            "bob", 1, plaintext,
        )
        assertEquals(AndroidSignalAdapter.ENVELOPE_PREKEY_INIT, first.envelopeType)
        val aliceSessionHandle = SpikeCryptoMaterial.SealedHandle(
            UUID.randomUUID(), CryptoRecordKind.SESSION
        )
        sessionVault().seal(
            aliceSessionHandle, CryptoRecordKind.SESSION, first.postEncryptSessionBytes
        )

        // Bob decrypts + seals through the production inbound seam.
        val decrypted = bobAdapter.decryptForInbox(
            localIdentity = bob.identity,
            localRegistrationId = bob.regId,
            signed = bob.signed,
            kyber = bob.kyber,
            otpks = bob.otpks,
            sessionBytes = org.signal.libsignal.protocol.state.SessionRecord().serialize(),
            pinnedRemoteIdentity = alice.identity.publicKey,
            remoteUsername = "alice",
            remoteSignalDeviceId = 2,
            envelopeType = AndroidSignalAdapter.ENVELOPE_PREKEY_INIT,
            ciphertext = first.ciphertextBytes,
        )
        assertArrayEquals(plaintext, decrypted.plaintext)
        val bobHandle = SessionEstablisher.sessionHandleFor(aliceDeviceId)
        // Snapshot before sealing: seal zeroes the caller's array by design.
        val bobPostDecrypt = decrypted.postDecryptSessionBytes.copyOf()
        sessionVault().seal(bobHandle, CryptoRecordKind.SESSION, decrypted.postDecryptSessionBytes)
        val now = System.currentTimeMillis()
        FileSessionMetadataStore(context).write(
            SignalSessionEntry(
                remoteDeviceId = aliceDeviceId,
                remoteUsername = "alice",
                remoteSignalDeviceId = 2,
                remoteRegistrationId = alice.regId,
                remoteIdentityPublicKeyB64 =
                    Base64.getEncoder().encodeToString(alice.identity.publicKey),
                establishedVia = EstablishedVia.WITH_OTPK,
                localIdentityHandleId = bob.identity.privateHandle.id.toString(),
                createdAt = now,
                updatedAt = now,
            )
        )

        // Bob replies (sender chain installed by the PREKEY decrypt).
        val reply = bobAdapter.encryptForSubmit(
            bob.identity, bob.regId,
            bobPostDecrypt, alice.identity.publicKey,
            "alice", 2, plaintext,
        )
        assertEquals(AndroidSignalAdapter.ENVELOPE_RATCHET, reply.envelopeType)

        // Durable inbox row exactly as the processor would persist it:
        // server messageId PK, exact wire bytes, sealed plaintext.
        val inboxMessageId = "33333333-3333-3333-3333-333333333333"
        val sealer = MessageContentSealer(AndroidKeystoreKeyProvider())
        val db = MessageDatabase.open(context)
        try {
            runBlocking {
                // Clean slate: an earlier recover run may have marked this
                // fixed test id ACKED (insert-ignore would keep it).
                db.messageDao().deleteMessage(inboxMessageId)
                db.messageDao().insertIgnore(
                    MessageEntity(
                        messageId = inboxMessageId,
                        conversationId = "44444444-4444-4444-4444-444444444444",
                        sequenceNumber = 1L,
                        direction = MessageDirection.IN,
                        senderDeviceId = aliceDeviceId,
                        recipientDeviceId = bobDeviceId,
                        envelopeType = AndroidSignalAdapter.ENVELOPE_PREKEY_INIT,
                        ciphertext = first.ciphertextBytes.copyOf(),
                        plaintextSealed = sealer.seal(inboxMessageId, plaintext),
                        sendState = null,
                        acked = false,
                        requestId = null,
                        serverMessageId = null,
                        serverTimestamp = "2026-10-02T10:00:00",
                        createdAt = System.currentTimeMillis(),
                    )
                )
                db.messageDao().upsertConversation(
                    ConversationEntity(
                        "44444444-4444-4444-4444-444444444444", 1L, 0L
                    )
                )
            }
        } finally {
            db.close()
        }

        phaseFile().writeText(
            listOf(
                "ALICE_IDENTITY_B64:" + Base64.getEncoder().encodeToString(alice.identity.publicKey),
                "BOB_IDENTITY_B64:" + Base64.getEncoder().encodeToString(bob.identity.publicKey),
                "ALICE_IDENTITY_HANDLE:${alice.identity.privateHandle.id}",
                "ALICE_SIGNED_HANDLE:${alice.signed.privateHandle.id}",
                "ALICE_KYBER_HANDLE:${alice.kyber.privateHandle.id}",
                "ALICE_OTPK_HANDLES:" + alice.otpks.joinToString(",") { it.privateHandle.id.toString() },
                "ALICE_SESSION_HANDLE:${aliceSessionHandle.id}",
                "BOB_IDENTITY_HANDLE:${bob.identity.privateHandle.id}",
                "BOB_SIGNED_HANDLE:${bob.signed.privateHandle.id}",
                "BOB_KYBER_HANDLE:${bob.kyber.privateHandle.id}",
                "BOB_OTPK_HANDLES:" + bob.otpks.joinToString(",") { it.privateHandle.id.toString() },
                "PREKEY1_B64:" + Base64.getEncoder().encodeToString(first.ciphertextBytes),
                "REPLY_B64:" + Base64.getEncoder().encodeToString(reply.ciphertextBytes),
                "INBOX_MESSAGE_ID:$inboxMessageId",
            ).joinToString("\n")
        )
        assertTrue(phaseFile().isFile)
    }

    @Test
    fun recoverPhase() {
        val lines = try {
            phaseFile().readLines()
        } catch (_: Exception) {
            throw AssertionError("phase file absent: run sealPhase first")
        }
        fun value(key: String): String =
            lines.first { it.startsWith("$key:") }.substringAfter(":")
        val aliceIdentity = Base64.getDecoder().decode(value("ALICE_IDENTITY_B64"))
        val bobIdentity = Base64.getDecoder().decode(value("BOB_IDENTITY_B64"))
        val replyBytes = Base64.getDecoder().decode(value("REPLY_B64"))
        val prekey1Bytes = Base64.getDecoder().decode(value("PREKEY1_B64"))

        // Fresh process, fresh adapters: only files + Keystore persist.
        val freshAlice = AndroidSignalAdapter()
        val freshBob = AndroidSignalAdapter()

        // Alice restores and decrypts Bob's RATCHET reply.
        val aliceLocal = restoreAs(
            freshAlice, CryptoRecordKind.IDENTITY, value("ALICE_IDENTITY_HANDLE")
        ).second as SpikeCryptoMaterial.Identity
        val aliceSigned = restoreAs(
            freshAlice, CryptoRecordKind.SIGNED_PREKEY, value("ALICE_SIGNED_HANDLE")
        ).second as SpikeCryptoMaterial.SignedPrekey
        val aliceKyber = restoreAs(
            freshAlice, CryptoRecordKind.KYBER_PREKEY, value("ALICE_KYBER_HANDLE")
        ).second as SpikeCryptoMaterial.KyberPrekey
        val aliceOtpks = value("ALICE_OTPK_HANDLES").split(",").map {
            restoreAs(freshAlice, CryptoRecordKind.ONE_TIME_PREKEY, it).second as SpikeCryptoMaterial.OneTimePrekey
        }
        // Alice restores and decrypts Bob's RATCHET reply. This block is
        // idempotent across repeated recover runs: the first run decrypts
        // and seals the advanced state; later runs hit the duplicate path
        // (the production ACK-without-redelivery proof, on device).
        val aliceSessionHandle =
            sessionHandleIn(value("ALICE_SESSION_HANDLE"), CryptoRecordKind.SESSION)
        val aliceSessionBytes = sessionVault().unseal(
            aliceSessionHandle,
            CryptoRecordKind.SESSION,
        )
        val alicePostReply: ByteArray = try {
            val replyDecrypted = freshAlice.decryptForInbox(
                localIdentity = aliceLocal,
                localRegistrationId = 4242,
                signed = aliceSigned,
                kyber = aliceKyber,
                otpks = aliceOtpks,
                sessionBytes = aliceSessionBytes,
                pinnedRemoteIdentity = bobIdentity,
                remoteUsername = "bob",
                remoteSignalDeviceId = 1,
                envelopeType = AndroidSignalAdapter.ENVELOPE_RATCHET,
                ciphertext = replyBytes,
            )
            assertArrayEquals(plaintext, replyDecrypted.plaintext)
            // Alice's advanced state re-seals (mirrors production
            // seal-before-ack). Snapshot first: seal zeroes the array.
            val advanced = replyDecrypted.postDecryptSessionBytes.copyOf()
            sessionVault().seal(
                aliceSessionHandle,
                CryptoRecordKind.SESSION,
                replyDecrypted.postDecryptSessionBytes,
            )
            advanced
        } catch (e: SessionCryptoException.DuplicateMessage) {
            // Already processed by an earlier recover: the sealed state is
            // the advanced one; proceed without delivering again.
            sessionVault().unseal(aliceSessionHandle, CryptoRecordKind.SESSION)
        }

        // Alice answers with RATCHET#2; Bob restores and decrypts it —
        // ratchet continuity for the inbox side across process death.
        // NOTE: RATCHET#2 differs on every recover run (fresh ephemeral
        // keys), so Bob always sees a new ciphertext here; duplicates
        // are proven separately below with the fixed PREKEY#1 bytes.
        val answer = freshAlice.encryptForSubmit(
            aliceLocal, 4242,
            alicePostReply, bobIdentity,
            "bob", 1, plaintext,
        )
        assertEquals(AndroidSignalAdapter.ENVELOPE_RATCHET, answer.envelopeType)

        val bobLocal = restoreAs(
            freshBob, CryptoRecordKind.IDENTITY, value("BOB_IDENTITY_HANDLE")
        ).second as SpikeCryptoMaterial.Identity
        val bobSigned = restoreAs(
            freshBob, CryptoRecordKind.SIGNED_PREKEY, value("BOB_SIGNED_HANDLE")
        ).second as SpikeCryptoMaterial.SignedPrekey
        val bobKyber = restoreAs(
            freshBob, CryptoRecordKind.KYBER_PREKEY, value("BOB_KYBER_HANDLE")
        ).second as SpikeCryptoMaterial.KyberPrekey
        val bobOtpks = value("BOB_OTPK_HANDLES").split(",").map {
            restoreAs(freshBob, CryptoRecordKind.ONE_TIME_PREKEY, it).second as SpikeCryptoMaterial.OneTimePrekey
        }
        // Bob's session entry + sealed post-decrypt state survived restart.
        val entry = FileSessionMetadataStore(context).read(aliceDeviceId)!!
        assertEquals("alice", entry.remoteUsername)
        val bobBlob = sessionVault().unseal(
            SessionEstablisher.sessionHandleFor(aliceDeviceId), CryptoRecordKind.SESSION
        )
        val bobDecrypted = freshBob.decryptForInbox(
            localIdentity = bobLocal,
            localRegistrationId = 7001,
            signed = bobSigned,
            kyber = bobKyber,
            otpks = bobOtpks,
            sessionBytes = bobBlob,
            pinnedRemoteIdentity = aliceIdentity,
            remoteUsername = "alice",
            remoteSignalDeviceId = 2,
            envelopeType = AndroidSignalAdapter.ENVELOPE_RATCHET,
            ciphertext = answer.ciphertextBytes,
        )
        assertArrayEquals(plaintext, bobDecrypted.plaintext)

        // The old PREKEY#1 still resolves as already-processed after
        // restart, so the ACK path stays valid without redelivery.
        assertThrows(SessionCryptoException.DuplicateMessage::class.java) {
            freshBob.decryptForInbox(
                localIdentity = bobLocal,
                localRegistrationId = 7001,
                signed = bobSigned,
                kyber = bobKyber,
                otpks = bobOtpks,
                sessionBytes = bobDecrypted.postDecryptSessionBytes,
                pinnedRemoteIdentity = aliceIdentity,
                remoteUsername = "alice",
                remoteSignalDeviceId = 2,
                envelopeType = AndroidSignalAdapter.ENVELOPE_PREKEY_INIT,
                ciphertext = prekey1Bytes,
            )
        }

        // The durable inbox row survived restart alongside the session:
        // exact bytes, sealed plaintext opens with the Keystore sealer.
        val rowDb = MessageDatabase.open(context)
        try {
            runBlocking {
                val row = rowDb.messageDao().byMessageId(value("INBOX_MESSAGE_ID"))!!
                assertEquals(MessageDirection.IN, row.direction)
                assertEquals(false, row.acked)
                assertArrayEquals(prekey1Bytes, row.ciphertext)
                assertArrayEquals(
                    plaintext,
                    MessageContentSealer(AndroidKeystoreKeyProvider()).open(
                        value("INBOX_MESSAGE_ID"), row.plaintextSealed!!
                    ),
                )
                assertEquals(1, rowDb.messageDao().markAcked(value("INBOX_MESSAGE_ID")))
                assertEquals(true, rowDb.messageDao().byMessageId(value("INBOX_MESSAGE_ID"))!!.acked)
            }
        } finally {
            rowDb.close()
        }
    }

    @Test
    fun keystoreDecryptContinuity_singleProcess() {
        val adapter = AndroidSignalAdapter()
        val alice = freshSide(adapter, 4242, 31, 41, 301)
        // Bob needs independent private material: a separate adapter so
        // no handle map is shared with Alice's side in this test.
        val bobAdapter = AndroidSignalAdapter()
        val bob = freshSide(bobAdapter, 7001, 11, 21, 101)
        val established = adapter.establishOutboundSession(
            alice.identity, alice.regId, "bob",
            bundleOf(
                bob.regId, 1, bob.identity.publicKey,
                bob.signed.prekeyId, bob.signed.publicKey, bob.signed.signature,
                bob.otpks.single().prekeyId, bob.otpks.single().publicKey,
                bob.kyber.prekeyId, bob.kyber.publicKey, bob.kyber.signature,
            ),
        )
        val first = adapter.encryptForSubmit(
            alice.identity, alice.regId,
            established.sessionBytes, bob.identity.publicKey,
            "bob", 1, plaintext,
        )
        val decrypted = bobAdapter.decryptForInbox(
            localIdentity = bob.identity,
            localRegistrationId = bob.regId,
            signed = bob.signed,
            kyber = bob.kyber,
            otpks = bob.otpks,
            sessionBytes = org.signal.libsignal.protocol.state.SessionRecord().serialize(),
            pinnedRemoteIdentity = alice.identity.publicKey,
            remoteUsername = "alice",
            remoteSignalDeviceId = 2,
            envelopeType = AndroidSignalAdapter.ENVELOPE_PREKEY_INIT,
            ciphertext = first.ciphertextBytes,
        )
        assertArrayEquals(plaintext, decrypted.plaintext)
        // Duplicate of the same ciphertext resolves as already-processed.
        assertThrows(SessionCryptoException.DuplicateMessage::class.java) {
            bobAdapter.decryptForInbox(
                localIdentity = bob.identity,
                localRegistrationId = bob.regId,
                signed = bob.signed,
                kyber = bob.kyber,
                otpks = bob.otpks,
                sessionBytes = decrypted.postDecryptSessionBytes,
                pinnedRemoteIdentity = alice.identity.publicKey,
                remoteUsername = "alice",
                remoteSignalDeviceId = 2,
                envelopeType = AndroidSignalAdapter.ENVELOPE_PREKEY_INIT,
                ciphertext = first.ciphertextBytes,
            )
        }
    }

    /** Restore one vault record; returns (handle, restored public wrapper). */
    private fun restoreAs(        adapter: AndroidSignalAdapter,
        kind: CryptoRecordKind,
        handleId: String,
    ): Pair<SpikeCryptoMaterial.SealedHandle, Any> {
        val handle = SpikeCryptoMaterial.SealedHandle(UUID.fromString(handleId), kind)
        val bytes = cryptoVault().unseal(handle, kind)
        return when (val r = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> handle to r.value
            is AndroidSignalAdapter.RestoredPublic.Signed -> handle to r.value
            is AndroidSignalAdapter.RestoredPublic.Kyber -> handle to r.value
            is AndroidSignalAdapter.RestoredPublic.OneTime -> handle to r.value
        }
    }
}
