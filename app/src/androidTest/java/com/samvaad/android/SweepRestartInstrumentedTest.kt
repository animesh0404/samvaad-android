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
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.ClaimedOneTimePrekey
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HistoryItem
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.InboxProcessor
import com.samvaad.android.session.InboxResult
import com.samvaad.android.session.MessageSender
import com.samvaad.android.session.RecoverOutcome
import com.samvaad.android.session.ReconciliationSweep
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SignalSessionEntry
import com.samvaad.android.session.SweepBounds
import java.io.File
import java.util.Base64
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device launch-recovery proof: REAL libsignal natives (device ABI),
 * REAL Keystore wrapping key, REAL Room file, REAL vault files. No live
 * server (scripted fakes), no TLS, no UI.
 *
 * Two phases driven from the host:
 *
 * 1. `sealPhase` — strand a SEALED outbound row (submit fails) and an
 *    unacked inbound row (ACK fails), and stage history wires. Phase
 *    file carries ONLY identifiers plus test ciphertext (never
 *    plaintext, never private material).
 * 2. Host runs `adb shell am force-stop com.samvaad.android` (and
 *    optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process, fresh objects: one sweep resubmits
 *    the identical outbox request, converges the inbox duplicate into
 *    an ACK, ingests history, and advances the cursor; a repeat sweep
 *    is a proven no-op.
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 */
@RunWith(AndroidJUnit4::class)
class SweepRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private companion object {
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val ALICE_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val CONV = "44444444-4444-4444-4444-444444444444"
        const val INBOX_MSG_ID = "33333333-3333-3333-3333-333333333333"
        const val HIST2_MSG_ID = "55555555-5555-5555-5555-555555555555"
        const val HIST3_MSG_ID = "66666666-6666-6666-6666-666666666666"
    }

    private val plaintext = "slice9-sweep-plaintext".toByteArray(Charsets.UTF_8)

    private fun cryptoVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider())

    private fun sessionVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider(), FileSessionMetadataStore.SUBDIR)

    private fun phaseFile(): File = File(context.cacheDir, "sweep-restart-phase.txt")

    /** Minimal scripted server: only the endpoints each phase needs. */
    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: (String) -> ClaimedDeviceBundle =
            { throw AssertionError("unexpected claim") }
        var submitHandler: (UUID, List<MessageEnvelopeSubmit>) -> SubmitMessageResult =
            { _, _ -> throw AssertionError("unexpected submit") }
        var fetchHandler: () -> List<MailboxItem> = { emptyList() }
        var ackHandler: (List<UUID>) -> Int = { ids -> ids.size }
        var historyHandler: (Long) -> List<HistoryItem> = { emptyList() }
        var serverCursor: Long = 0L
        var advanceHandler: (Long) -> Long = { through ->
            serverCursor = maxOf(serverCursor, through)
            serverCursor
        }
        val submits = mutableListOf<Pair<UUID, List<MessageEnvelopeSubmit>>>()
        val ackedBatches = mutableListOf<List<UUID>>()
        val advanceCalls = mutableListOf<Long>()

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment")
        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload")
        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = throw AssertionError("no owner list")
        override suspend fun approveDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no approval in this slice")

        override suspend fun bindDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            recoveryCode: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no recovery in this slice")

        override suspend fun recoverEnroll(
            session: AuthSession,
            serverAddress: String,
            recoveryCode: String,
            request: com.samvaad.android.enroll.EnrollRequest,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no recovery in this slice")

        override suspend fun listRecipientDevices(
            session: AuthSession, serverAddress: String, username: String,
        ): List<RecipientDeviceRecord> = directoryHandler(username)
        override suspend fun claimOneTimePrekey(
            session: AuthSession, serverAddress: String, deviceId: String, requestId: UUID,
        ): ClaimedDeviceBundle = claimHandler(deviceId)
        override suspend fun submitMessage(
            session: AuthSession, serverAddress: String, requestId: UUID,
            envelopes: List<MessageEnvelopeSubmit>,
        ): SubmitMessageResult {
            submits.add(requestId to envelopes.map { it.copy() })
            return submitHandler(requestId, envelopes)
        }
        override suspend fun fetchMailbox(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<MailboxItem> = fetchHandler()
        override suspend fun ackMailbox(
            session: AuthSession, serverAddress: String, messageIds: List<UUID>,
        ): Int {
            ackedBatches.add(messageIds.toList())
            return ackHandler(messageIds)
        }
        override suspend fun fetchHistory(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<HistoryItem> = historyHandler(afterSequence)
        override suspend fun getSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
        ): SyncCursor = SyncCursor(conversationId, serverCursor)
        override suspend fun advanceSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncCursor {
            advanceCalls.add(throughSequence)
            return SyncCursor(conversationId, advanceHandler(throughSequence))
        }
    }

    private val session = AuthSession(
        identifier = "bob",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private data class Fixtures(
        val adapter: AndroidSignalAdapter,
        val identityB64: String,
        val signedId: Int,
        val signedB64: String,
        val signedSigB64: String,
        val kyberId: Int,
        val kyberB64: String,
        val kyberSigB64: String,
        val otkIds: List<Int>,
        val otkB64s: List<String>,
    )

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun sealLocalDevice(adapter: AndroidSignalAdapter): Fixtures {
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..3).map { adapter.generateOneTimePrekey(5000 + it) }
        val vault = cryptoVault()
        vault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        vault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        vault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            vault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = LOCAL_DEVICE_ID,
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = b64(identity.publicKey),
                signedPrekeyId = signed.prekeyId,
                kyberPrekeyId = kyber.prekeyId,
                otpkHighWaterMark = 5003,
                roleHint = "PRIMARY",
                statusHint = "ACTIVE",
                identityHandleId = identity.privateHandle.id.toString(),
                signedHandleId = signed.privateHandle.id.toString(),
                kyberHandleId = kyber.privateHandle.id.toString(),
                otpkHandleIds = otpks.map { it.privateHandle.id.toString() },
                codesAcknowledged = true,
            )
        )
        return Fixtures(
            adapter, b64(identity.publicKey),
            signed.prekeyId, b64(signed.publicKey), b64(signed.signature),
            kyber.prekeyId, b64(kyber.publicKey), b64(kyber.signature),
            otpks.map { it.prekeyId }, otpks.map { b64(it.publicKey) },
        )
    }

    private data class Peer(
        val adapter: AndroidSignalAdapter,
        val identity: SpikeCryptoMaterial.Identity,
        val regId: Int,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private fun freshPeer(): Peer {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return Peer(
            adapter, identity, 7001,
            adapter.generateSignedPrekey(identity, 11),
            adapter.generateKyberPrekey(identity, 21),
            listOf(adapter.generateOneTimePrekey(101)),
        )
    }

    private fun establishBobToAlice(
        api: FakeApi,
        adapter: AndroidSignalAdapter,
        locks: SessionDeviceLocks,
        db: MessageDatabase,
        sealer: MessageContentSealer,
        peer: Peer,
    ) {
        val otk = peer.otpks.single()
        fun pb(bytes: ByteArray) = b64(bytes)
        api.directoryHandler = {
            listOf(
                RecipientDeviceRecord(
                    deviceId = ALICE_DEVICE_ID,
                    registrationId = peer.regId,
                    signalDeviceId = 2,
                    deviceIdentityPublicKey = pb(peer.identity.publicKey),
                    signedPrekeyId = peer.signed.prekeyId,
                    signedPrekey = pb(peer.signed.publicKey),
                    signedPrekeySignature = pb(peer.signed.signature),
                    hasAvailableOneTimePrekey = true,
                    deviceRole = "COMPANION",
                    kyberPrekeyId = peer.kyber.prekeyId,
                    kyberPrekey = pb(peer.kyber.publicKey),
                    kyberPrekeySignature = pb(peer.kyber.signature),
                )
            )
        }
        api.claimHandler = { id ->
            ClaimedDeviceBundle(
                deviceId = id,
                registrationId = peer.regId,
                signalDeviceId = 2,
                deviceIdentityPublicKey = pb(peer.identity.publicKey),
                signedPrekeyId = peer.signed.prekeyId,
                signedPrekey = pb(peer.signed.publicKey),
                signedPrekeySignature = pb(peer.signed.signature),
                oneTimePrekey = ClaimedOneTimePrekey(otk.prekeyId, pb(otk.publicKey)),
                deviceRole = "COMPANION",
                kyberPrekeyId = peer.kyber.prekeyId,
                kyberPrekey = pb(peer.kyber.publicKey),
                kyberPrekeySignature = pb(peer.kyber.signature),
            )
        }
        val establisher = SessionEstablisher(
            api, FileDeviceMetadataStore(context), FileSessionMetadataStore(context),
            adapter, cryptoVault(), sessionVault(),
        )
        val result = runBlocking { establisher.establish(session, server, "alice", ALICE_DEVICE_ID) }
        assertTrue(result is SessionEstablishResult.Established)
    }

    private fun sweep(
        api: FakeApi,
        adapter: AndroidSignalAdapter,
        locks: SessionDeviceLocks,
        db: MessageDatabase,
        sealer: MessageContentSealer,
        bounds: SweepBounds = SweepBounds(),
    ) = ReconciliationSweep(
        api = api,
        localMetadata = FileDeviceMetadataStore(context),
        sessions = FileSessionMetadataStore(context),
        adapter = adapter,
        cryptoVault = cryptoVault(),
        sessionVault = sessionVault(),
        deviceLocks = locks,
        db = db,
        contentSealer = sealer,
        bounds = bounds,
    )

    private fun successResult(createdNew: Boolean = true) = SubmitMessageResult(
        "33333333-3333-3333-3333-333333333333", CONV, 7L,
        "2026-10-02T10:00:00", listOf(ALICE_DEVICE_ID), createdNew,
    )

    private fun mailboxItem(
        senderDeviceId: String,
        envelopeType: String,
        ciphertext: ByteArray,
        messageId: String,
        sequenceNumber: Long,
    ) = MailboxItem(
        messageId = messageId,
        conversationId = CONV,
        sequenceNumber = sequenceNumber,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = b64(ciphertext),
        serverTimestamp = "2026-10-02T10:00:00",
    )

    private fun historyItem(
        senderDeviceId: String,
        envelopeType: String,
        ciphertext: ByteArray,
        messageId: String,
        sequenceNumber: Long,
    ) = HistoryItem(
        messageId = messageId,
        conversationId = CONV,
        sequenceNumber = sequenceNumber,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = b64(ciphertext),
        serverTimestamp = "2026-10-02T10:00:00",
    )

    @Test
    fun sealPhase() {
        phaseFile().delete()
        // Fresh device state: reinstalls preserve app data, and stale
        // vault/metadata/Room rows from earlier runs (same test device
        // IDs, different keys) would poison identity pinning.
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, MessageDatabase.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "session").deleteRecursively()
        val api = FakeApi()
        val adapter = AndroidSignalAdapter()
        val locks = SessionDeviceLocks()
        val bob = sealLocalDevice(adapter)
        val alice = freshPeer()
        establishBobToAlice(api, adapter, locks, MessageDatabase.open(context).also { it.close() }, MessageContentSealer(AndroidKeystoreKeyProvider()), alice)
        val db = MessageDatabase.open(context)

        // 1) Strand a SEALED outbound row: submit fails with transport.
        var failSubmit = true
        api.submitHandler = { _, _ ->
            if (failSubmit) {
                failSubmit = false
                throw EnrollException.Transport()
            }
            successResult(createdNew = false)
        }
        val sender = MessageSender(
            api, FileDeviceMetadataStore(context), FileSessionMetadataStore(context),
            adapter, cryptoVault(), sessionVault(), locks, db,
            MessageContentSealer(AndroidKeystoreKeyProvider()),
        )
        val first = runBlocking { sender.send(session, server, "alice", ALICE_DEVICE_ID, plaintext) }
        assertTrue(first is SendResult.Failed)
        val stranded = api.submits.single()

        // 2) Strand an unacked inbound row: ACK fails with transport.
        val established = alice.adapter.establishOutboundSession(
            alice.identity, alice.regId, "bob",
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = Base64.getDecoder().decode(bob.identityB64),
                signedPrekeyId = bob.signedId,
                signedPrekey = Base64.getDecoder().decode(bob.signedB64),
                signedPrekeySignature = Base64.getDecoder().decode(bob.signedSigB64),
                oneTimePrekeyId = bob.otkIds[0],
                oneTimePrekey = Base64.getDecoder().decode(bob.otkB64s[0]),
                kyberPrekeyId = bob.kyberId,
                kyberPrekey = Base64.getDecoder().decode(bob.kyberB64),
                kyberPrekeySignature = Base64.getDecoder().decode(bob.kyberSigB64),
            ),
        )
        val encrypted = alice.adapter.encryptForSubmit(
            alice.identity, alice.regId,
            established.sessionBytes, Base64.getDecoder().decode(bob.identityB64),
            "bob", 1, plaintext,
        )
        var failAck = true
        api.fetchHandler = {
            listOf(mailboxItem(ALICE_DEVICE_ID, encrypted.envelopeType, encrypted.ciphertextBytes, INBOX_MSG_ID, 1L))
        }
        api.ackHandler = { ids ->
            if (failAck) throw EnrollException.Transport()
            ids.size
        }
        val inbox = InboxProcessor(
            api, FileDeviceMetadataStore(context), FileSessionMetadataStore(context),
            adapter, cryptoVault(), sessionVault(), locks, db,
            MessageContentSealer(AndroidKeystoreKeyProvider()),
        )
        val received = runBlocking { inbox.receive(session, server) }
            as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, received.messages.size)
        assertEquals(listOf(INBOX_MSG_ID), received.unacked)

        // 3) Stage history wires (seq 2,3) for the recover run.
        val established2 = alice.adapter.establishOutboundSession(
            alice.identity, alice.regId, "bob",
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = Base64.getDecoder().decode(bob.identityB64),
                signedPrekeyId = bob.signedId,
                signedPrekey = Base64.getDecoder().decode(bob.signedB64),
                signedPrekeySignature = Base64.getDecoder().decode(bob.signedSigB64),
                oneTimePrekeyId = bob.otkIds[1],
                oneTimePrekey = Base64.getDecoder().decode(bob.otkB64s[1]),
                kyberPrekeyId = bob.kyberId,
                kyberPrekey = Base64.getDecoder().decode(bob.kyberB64),
                kyberPrekeySignature = Base64.getDecoder().decode(bob.kyberSigB64),
            ),
        )
        val second = alice.adapter.encryptForSubmit(
            alice.identity, alice.regId,
            established2.sessionBytes, Base64.getDecoder().decode(bob.identityB64),
            "bob", 1, plaintext,
        )
        db.close()
        phaseFile().writeText(
            listOf(
                "SEALED_REQID:${stranded.first}",
                "SEALED_CT_B64:${stranded.second.single().ciphertextBase64}",
                "INBOX_MSG_ID:$INBOX_MSG_ID",
                "INBOX_CT_B64:${b64(encrypted.ciphertextBytes)}",
                "INBOX_CT_TYPE:${encrypted.envelopeType}",
                "HIST2_B64:${b64(second.ciphertextBytes)}",
                "HIST2_TYPE:${second.envelopeType}",
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
        val sealedReqId = value("SEALED_REQID")
        val sealedCtB64 = value("SEALED_CT_B64")
        val inboxId = value("INBOX_MSG_ID")
        val inboxBytes = Base64.getDecoder().decode(value("INBOX_CT_B64"))
        val inboxType = value("INBOX_CT_TYPE")
        val hist2Bytes = Base64.getDecoder().decode(value("HIST2_B64"))
        val hist2Type = value("HIST2_TYPE")

        // Fresh process, fresh objects: only files + Keystore persist.
        val api = FakeApi()
        val adapter = AndroidSignalAdapter()
        val locks = SessionDeviceLocks()
        val db = MessageDatabase.open(context)
        val sealer = MessageContentSealer(AndroidKeystoreKeyProvider())
        try {
            // Transport healed: the stranded SEALED row replays to 200.
            api.submitHandler = { _, _ -> successResult(createdNew = false) }
            api.fetchHandler = {
                listOf(
                    mailboxItem(
                        ALICE_DEVICE_ID, inboxType, inboxBytes, inboxId, 1L,
                    )
                )
            }
            val hist2Id = "77777777-7777-7777-7777-777777777777"
            api.historyHandler = { after ->
                if (after < 2L) {
                    listOf(historyItem(ALICE_DEVICE_ID, hist2Type, hist2Bytes, hist2Id, 2L))
                } else {
                    emptyList()
                }
            }
            // Outbox: identical resubmission of the stranded SEALED row —
            // or nothing, if an earlier recover already converged it (the
            // repeat-invocation case below re-enters here). Gate on the
            // actual pre-sweep row state so a broken seal still fails.
            // (Same pre-read for history below: post-sweep reads cannot
            // distinguish fresh stores from pre-existing rows.)
            val preSealed = runBlocking { db.messageDao().pendingOutbox() }
                .filter { it.sendState == SendState.SEALED }
            val preHistExists = runBlocking { db.messageDao().byMessageId(hist2Id) } != null
            val report = runBlocking {
                sweep(api, adapter, locks, db, sealer).sweep(session, server)
            }
            if (preSealed.isEmpty()) {
                assertTrue(report.outboxRecovered.isEmpty())
                assertTrue(api.submits.isEmpty())
            } else {
                val resubmitted = report.outboxRecovered.single() as RecoverOutcome.Resubmitted
                assertFalse(resubmitted.sent.createdNew)
                assertEquals(1, api.submits.size)
                assertEquals(sealedReqId, api.submits.single().first.toString())
                assertEquals(sealedCtB64, api.submits.single().second.single().ciphertextBase64)
            }
            // Inbox: redelivery of the exact bytes hits the duplicate
            // path (no plaintext), ACKs, and marks.
            val inboxResult = report.inbox as com.samvaad.android.session.InboxResult.Completed
            assertTrue(inboxResult.messages.isEmpty())
            assertEquals(listOf(inboxId), inboxResult.acked)
            // History: seq 2 ingested durably with sealed plaintext —
            // or already present from an earlier recover (repeat case,
            // where the fetch correctly returns nothing new).
            // NOTE: histFresh was read pre-sweep above; post-sweep reads
            // cannot distinguish fresh stores from pre-existing rows.
            if (preHistExists) {
                assertEquals(0, report.historyStored)
            } else {
                assertEquals(1, report.historyStored)
            }
            val stored = runBlocking { db.messageDao().byMessageId(hist2Id) }!!
            assertArrayEquals(hist2Bytes, stored.ciphertext)
            assertArrayEquals(
                plaintext, sealer.open(hist2Id, stored.plaintextSealed!!)
            )
            // Cursor advanced through contiguous 1,2 on the fresh run;
            // already there on a repeat (no regression, no rewrite).
            if (preHistExists) {
                assertTrue(report.cursorsAdvanced.isEmpty())
            } else {
                assertEquals(mapOf(CONV to 2L), report.cursorsAdvanced)
            }
            // Repeat sweep: converged no-op (no new submits/messages).
            // Submit count is gated the same way: only a fresh run submits.
            val submitsBeforeRepeat = api.submits.size
            val again = runBlocking {
                sweep(api, adapter, locks, db, sealer).sweep(session, server)
            }
            assertTrue(again.outboxRecovered.isEmpty())
            assertEquals(submitsBeforeRepeat, api.submits.size)
            val againInbox = again.inbox as com.samvaad.android.session.InboxResult.Completed
            assertTrue(againInbox.messages.isEmpty())
        } finally {
            db.close()
        }
    }
}
