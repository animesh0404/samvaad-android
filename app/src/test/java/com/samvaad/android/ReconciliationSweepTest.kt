package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.WrappingKeyProvider
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
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.InboxResult
import com.samvaad.android.session.RecoverOutcome
import com.samvaad.android.session.ReconciliationSweep
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SweepBounds
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Launch-time reconciliation sweep tests with a scripted fake API and
 * REAL crypto/vault/Room (ephemeral AES key standing in for Keystore).
 * No network, no UI.
 *
 * Each test drives a deterministic fake server: directory/claim for
 * establishment, submit/ack/history/cursor handlers with capture. Peer
 * devices are independent adapters producing genuine wire ciphertext,
 * so every decrypt/encrypt in the sweep exercises real libsignal.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ReconciliationSweepTest {

    companion object {
        val PLAINTEXT = "slice9-sweep-plaintext".toByteArray(Charsets.UTF_8)
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val ALICE_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val ALICE_USERNAME = "alice"
        const val CONV = "44444444-4444-4444-4444-444444444444"
    }

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key
    }

    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: suspend (String, UUID) -> ClaimedDeviceBundle =
            { _, _ -> throw AssertionError("unexpected claim") }
        var submitHandler: suspend (UUID, List<MessageEnvelopeSubmit>) -> SubmitMessageResult =
            { _, _ -> throw AssertionError("unexpected submit") }
        var fetchHandler: () -> List<MailboxItem> = { emptyList() }
        var ackHandler: suspend (List<UUID>) -> Int = { ids -> ids.size }
        var historyHandler: suspend (String, Long, Int) -> List<HistoryItem> = { _, _, _ -> emptyList() }
        // Stateful server cursor: monotonic like the real one (advance
        // stores max, reads return current). Tests override per case.
        var serverCursor: Long = 0L
        var getCursorHandler: suspend (String) -> Long = { serverCursor }
        var advanceHandler: suspend (String, Long) -> Long = { _, through ->
            serverCursor = maxOf(serverCursor, through)
            serverCursor
        }
        var directoryCalls = 0
        var claimCalls = 0
        var submitCalls = 0
        val submits = mutableListOf<Pair<UUID, List<MessageEnvelopeSubmit>>>()
        val ackedBatches = mutableListOf<List<UUID>>()
        val historyCalls = mutableListOf<Triple<String, Long, Int>>()
        val advanceCalls = mutableListOf<Pair<String, Long>>()

        private fun okSubmit(createdNew: Boolean = true) = SubmitMessageResult(
            "33333333-3333-3333-3333-333333333333", CONV, 7L,
            "2026-10-02T10:00:00", listOf(ALICE_DEVICE_ID), createdNew,
        )

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment in this slice")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload in this slice")

        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = throw AssertionError("no owner list in this slice")

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

        override suspend fun beginAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): com.samvaad.android.enroll.AttachBegin =
            throw AssertionError("no attach in this slice")

        override suspend fun completeAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            challengeId: String,
            proofBase64: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no attach in this slice")

        override suspend fun recoverEnroll(
            session: AuthSession,
            serverAddress: String,
            recoveryCode: String,
            request: com.samvaad.android.enroll.EnrollRequest,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no recovery in this slice")

        override suspend fun listRecipientDevices(
            session: AuthSession, serverAddress: String, username: String,
        ): List<RecipientDeviceRecord> {
            directoryCalls++
            return directoryHandler(username)
        }

        override suspend fun claimOneTimePrekey(
            session: AuthSession, serverAddress: String, deviceId: String, requestId: UUID,
        ): ClaimedDeviceBundle {
            claimCalls++
            return claimHandler(deviceId, requestId)
        }

        override suspend fun submitMessage(
            session: AuthSession, serverAddress: String, requestId: UUID,
            envelopes: List<MessageEnvelopeSubmit>,
        ): SubmitMessageResult {
            submitCalls++
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
        ): List<HistoryItem> {
            historyCalls.add(Triple(conversationId, afterSequence, limit))
            return historyHandler(conversationId, afterSequence, limit)
        }

        override suspend fun getSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
        ): SyncCursor = SyncCursor(conversationId, getCursorHandler(conversationId))

        override suspend fun listConversations(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<String> =
            throw AssertionError("no conversation list in this test")

        override suspend fun uploadSyncBatch(
            session: AuthSession,
            serverAddress: String,
            request: com.samvaad.android.enroll.SyncUploadRequest,
        ): com.samvaad.android.enroll.SyncUploadResult =
            throw AssertionError("no history sync in this test")

        override suspend fun fetchSyncBatch(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<com.samvaad.android.enroll.SyncBatchItem> =
            throw AssertionError("no history sync in this test")

        override suspend fun ackSync(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncAckResult =
            throw AssertionError("no history sync in this test")

        override suspend fun advanceSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncCursor {
            advanceCalls.add(conversationId to throughSequence)
            return SyncCursor(conversationId, advanceHandler(conversationId, throughSequence))
        }

        fun okSubmitPublic(createdNew: Boolean = true) = okSubmit(createdNew)
    }

    private data class PeerKeys(
        val adapter: AndroidSignalAdapter,
        val deviceId: String,
        val username: String,
        val signalId: Int,
        val regId: Int,
        val identity: SpikeCryptoMaterial.Identity,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private data class LocalPublics(
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

    private fun freshPeer(deviceId: String, username: String, signalId: Int, regId: Int): PeerKeys {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return PeerKeys(
            adapter, deviceId, username, signalId, regId, identity,
            adapter.generateSignedPrekey(identity, 11),
            adapter.generateKyberPrekey(identity, 21),
            listOf(adapter.generateOneTimePrekey(101)),
        )
    }

    private lateinit var context: Context
    private lateinit var api: FakeApi
    private lateinit var keys: EphemeralKeys
    private lateinit var adapter: AndroidSignalAdapter
    private lateinit var cryptoVault: AndroidCryptoVault
    private lateinit var sessionVault: AndroidCryptoVault
    private lateinit var localMeta: FileDeviceMetadataStore
    private lateinit var sessionMeta: FileSessionMetadataStore
    private lateinit var locks: SessionDeviceLocks
    private lateinit var db: MessageDatabase
    private lateinit var sealer: MessageContentSealer

    private val session = AuthSession(
        identifier = "bob",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private fun sweep(bounds: SweepBounds = SweepBounds()) = ReconciliationSweep(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = adapter,
        cryptoVault = cryptoVault,
        sessionVault = sessionVault,
        deviceLocks = locks,
        db = db,
        contentSealer = sealer,
        bounds = bounds,
    )

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, MessageDatabase.SUBDIR).deleteRecursively()
        api = FakeApi()
        keys = EphemeralKeys()
        adapter = AndroidSignalAdapter()
        cryptoVault = AndroidCryptoVault(context, keys)
        sessionVault = AndroidCryptoVault(context, keys, FileSessionMetadataStore.SUBDIR)
        localMeta = FileDeviceMetadataStore(context)
        sessionMeta = FileSessionMetadataStore(context)
        locks = SessionDeviceLocks()
        db = androidx.room.Room.inMemoryDatabaseBuilder(context, MessageDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        sealer = MessageContentSealer(keys)
        api.submitHandler = { _, _ -> api.okSubmitPublic() }
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun sealLocalDevice(): LocalPublics {
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..3).map { adapter.generateOneTimePrekey(5000 + it) }
        cryptoVault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        cryptoVault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        cryptoVault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            cryptoVault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
        localMeta.writeAdopted(
            AdoptedDevice(
                deviceId = LOCAL_DEVICE_ID,
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
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
        return LocalPublics(
            identityB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
            signedId = signed.prekeyId,
            signedB64 = SpikeCryptoMaterial.encodeBase64(signed.publicKey),
            signedSigB64 = SpikeCryptoMaterial.encodeBase64(signed.signature),
            kyberId = kyber.prekeyId,
            kyberB64 = SpikeCryptoMaterial.encodeBase64(kyber.publicKey),
            kyberSigB64 = SpikeCryptoMaterial.encodeBase64(kyber.signature),
            otkIds = otpks.map { it.prekeyId },
            otkB64s = otpks.map { SpikeCryptoMaterial.encodeBase64(it.publicKey) },
        )
    }

    private fun bobEstablishesTo(peer: PeerKeys) {
        val otk = peer.otpks.single()
        fun b64(bytes: ByteArray) = SpikeCryptoMaterial.encodeBase64(bytes)
        api.directoryHandler = {
            listOf(
                RecipientDeviceRecord(
                    deviceId = peer.deviceId,
                    registrationId = peer.regId,
                    signalDeviceId = peer.signalId,
                    deviceIdentityPublicKey = b64(peer.identity.publicKey),
                    signedPrekeyId = peer.signed.prekeyId,
                    signedPrekey = b64(peer.signed.publicKey),
                    signedPrekeySignature = b64(peer.signed.signature),
                    hasAvailableOneTimePrekey = true,
                    deviceRole = "COMPANION",
                    kyberPrekeyId = peer.kyber.prekeyId,
                    kyberPrekey = b64(peer.kyber.publicKey),
                    kyberPrekeySignature = b64(peer.kyber.signature),
                )
            )
        }
        api.claimHandler = { id, _ ->
            ClaimedDeviceBundle(
                deviceId = id,
                registrationId = peer.regId,
                signalDeviceId = peer.signalId,
                deviceIdentityPublicKey = b64(peer.identity.publicKey),
                signedPrekeyId = peer.signed.prekeyId,
                signedPrekey = b64(peer.signed.publicKey),
                signedPrekeySignature = b64(peer.signed.signature),
                oneTimePrekey = ClaimedOneTimePrekey(otk.prekeyId, b64(otk.publicKey)),
                deviceRole = "COMPANION",
                kyberPrekeyId = peer.kyber.prekeyId,
                kyberPrekey = b64(peer.kyber.publicKey),
                kyberPrekeySignature = b64(peer.kyber.signature),
            )
        }
        val establisher = SessionEstablisher(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault
        )
        val result = runBlocking {
            establisher.establish(session, server, peer.username, peer.deviceId)
        }
        assertTrue(result is SessionEstablishResult.Established)
    }

    /** Peer establishes outbound to Bob and encrypts; returns wire + type. */
    private fun peerEncrypts(peer: PeerKeys, bob: LocalPublics): Pair<ByteArray, String> {
        fun b64(bytes: ByteArray) = SpikeCryptoMaterial.encodeBase64(bytes)
        val established = peer.adapter.establishOutboundSession(
            peer.identity, peer.regId, "bob",
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = SpikeCryptoMaterial.decodeBase64(bob.identityB64),
                signedPrekeyId = bob.signedId,
                signedPrekey = SpikeCryptoMaterial.decodeBase64(bob.signedB64),
                signedPrekeySignature = SpikeCryptoMaterial.decodeBase64(bob.signedSigB64),
                oneTimePrekeyId = bob.otkIds[0],
                oneTimePrekey = SpikeCryptoMaterial.decodeBase64(bob.otkB64s[0]),
                kyberPrekeyId = bob.kyberId,
                kyberPrekey = SpikeCryptoMaterial.decodeBase64(bob.kyberB64),
                kyberPrekeySignature = SpikeCryptoMaterial.decodeBase64(bob.kyberSigB64),
            ),
        )
        val encrypted = peer.adapter.encryptForSubmit(
            peer.identity, peer.regId,
            established.sessionBytes, SpikeCryptoMaterial.decodeBase64(bob.identityB64),
            "bob", 1, PLAINTEXT,
        )
        return encrypted.ciphertextBytes to encrypted.envelopeType
    }

    private fun mailboxItem(
        senderDeviceId: String,
        envelopeType: String,
        ciphertext: ByteArray,
        messageId: UUID = UUID.randomUUID(),
        conversationId: String = CONV,
        sequenceNumber: Long = 1L,
    ) = MailboxItem(
        messageId = messageId.toString(),
        conversationId = conversationId,
        sequenceNumber = sequenceNumber,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(ciphertext),
        serverTimestamp = "2026-10-02T10:00:00",
    )

    private fun historyItem(
        senderDeviceId: String,
        envelopeType: String,
        ciphertext: ByteArray,
        messageId: UUID = UUID.randomUUID(),
        conversationId: String = CONV,
        sequenceNumber: Long = 1L,
    ) = HistoryItem(
        messageId = messageId.toString(),
        conversationId = conversationId,
        sequenceNumber = sequenceNumber,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(ciphertext),
        serverTimestamp = "2026-10-02T10:00:00",
    )

    private fun dao() = db.messageDao()

    private fun row(messageId: String) = runBlocking { dao().byMessageId(messageId) }

    // ---- outbound recovery through the sweep ----

    @Test
    fun sweep_recoversSealedOutbound_identically() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        // Drive a real send that strands SEALED: transport fails once.
        var failFirst = true
        api.submitHandler = { _, _ ->
            if (failFirst) {
                failFirst = false
                throw EnrollException.Transport()
            }
            api.okSubmitPublic(createdNew = false)
        }
        val sender = com.samvaad.android.session.MessageSender(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault, locks, db, sealer
        )
        val first = runBlocking { sender.send(session, server, ALICE_USERNAME, ALICE_DEVICE_ID, PLAINTEXT) }
        assertTrue(first is SendResult.Failed)
        val original = api.submits.single()

        // The sweep resubmits the identical request and marks SENT.
        val report = runBlocking { sweep().sweep(session, server) }
        assertEquals(1, report.outboxRecovered.size)
        val resubmitted = report.outboxRecovered.single() as RecoverOutcome.Resubmitted
        assertFalse(resubmitted.sent.createdNew)
        assertEquals(2, api.submits.size)
        assertEquals(original.first, api.submits[1].first)
        assertEquals(
            original.second.single().ciphertextBase64,
            api.submits[1].second.single().ciphertextBase64,
        )
        assertEquals(SendState.SENT, row(resubmitted.messageId)!!.sendState)
        assertTrue(report.outboxSkippedDevices.isEmpty())
        assertNull(report.outboxError)
    }

    @Test
    fun sweep_supersedesPendingSeal_freshIds() {
        sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val staleId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        val staleRequest = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        runBlocking {
            dao().insertIgnore(
                MessageEntity(
                    messageId = staleId,
                    conversationId = "",
                    sequenceNumber = 0L,
                    direction = MessageDirection.OUT,
                    senderDeviceId = LOCAL_DEVICE_ID,
                    recipientDeviceId = ALICE_DEVICE_ID,
                    envelopeType = "PREKEY_INIT",
                    ciphertext = ByteArray(32) { 0x2A },
                    plaintextSealed = sealer.seal(staleId, PLAINTEXT),
                    sendState = SendState.PENDING_SEAL,
                    acked = false,
                    requestId = staleRequest,
                    serverMessageId = null,
                    serverTimestamp = "",
                    createdAt = 1L,
                )
            )
        }
        val report = runBlocking { sweep().sweep(session, server) }
        val superseded = report.outboxRecovered.single() as RecoverOutcome.Superseded
        assertEquals(staleId, superseded.oldMessageId)
        assertNull(row(staleId))
        assertTrue(superseded.fresh is SendResult.Sent)
        assertTrue(api.submits.none { it.first.toString() == staleRequest })
    }

    @Test
    fun sweep_ignoresSentRows_secondSweepNoop() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val sender = com.samvaad.android.session.MessageSender(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault, locks, db, sealer
        )
        runBlocking { sender.send(session, server, ALICE_USERNAME, ALICE_DEVICE_ID, PLAINTEXT) }
        val submitsAfterSend = api.submits.size
        val first = runBlocking { sweep().sweep(session, server) }
        assertTrue(first.outboxRecovered.isEmpty())
        // Mailbox/history/cursor branches run against empty fakes.
        assertTrue(first.inbox is InboxResult.Completed)
        val second = runBlocking { sweep().sweep(session, server) }
        assertTrue(second.outboxRecovered.isEmpty())
        assertEquals(submitsAfterSend, api.submits.size)
        assertNull(second.outboxError)
        assertNull(second.inboxError)
        assertNull(second.historyError)
        assertNull(second.cursorError)
    }

    // ---- inbound convergence through the sweep ----

    @Test
    fun sweep_convergesUnackedRow_viaDuplicate() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        var failAck = true
        api.ackHandler = { ids ->
            if (failAck) throw EnrollException.Transport()
            ids.size
        }
        // First sweep: plaintext delivered once, ACK fails server-side.
        val first = runBlocking { sweep().sweep(session, server) }
        val completed = first.inbox as InboxResult.Completed
        assertEquals(1, completed.messages.size)
        assertEquals(listOf(item.messageId), completed.unacked)
        assertEquals(false, row(item.messageId)!!.acked)

        // Second sweep: redelivery hits the duplicate path, ACKs, marks.
        failAck = false
        val second = runBlocking { sweep().sweep(session, server) }
        val redelivered = second.inbox as InboxResult.Completed
        assertTrue(redelivered.messages.isEmpty())
        assertEquals(listOf(item.messageId), redelivered.acked)
        assertEquals(true, row(item.messageId)!!.acked)
    }

    @Test
    fun sweep_emptyMailbox_preservesPlaintext() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        runBlocking { sweep().sweep(session, server) }
        api.fetchHandler = { emptyList() }
        val second = runBlocking { sweep().sweep(session, server) }
        val completed = second.inbox as InboxResult.Completed
        assertTrue(completed.messages.isEmpty())
        // Plaintext remains openable from the durable row.
        val stored = row(item.messageId)!!
        assertArrayEquals(PLAINTEXT, sealer.open(item.messageId, stored.plaintextSealed!!))
    }

    // ---- history + cursor through the sweep ----

    @Test
    fun sweep_ingestsHistoryPage_andAdvancesCursor() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        // History reconciliation covers locally known conversations:
        // seed the anchor (mailbox receives create these in production).
        runBlocking {
            db.messageDao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(CONV, 0L, 0L)
            )
        }
        val (wire1, type1) = peerEncrypts(alice, bob)
        val (wire2, type2) = peerEncrypts(alice, bob)
        val h1 = historyItem(ALICE_DEVICE_ID, type1, wire1, sequenceNumber = 1L)
        val h2 = historyItem(ALICE_DEVICE_ID, type2, wire2, sequenceNumber = 2L)
        var pages = 0
        api.historyHandler = { conv, after, _ ->
            pages++
            assertEquals(CONV, conv)
            if (after == 0L) listOf(h1, h2) else emptyList()
        }
        val report = runBlocking { sweep().sweep(session, server) }
        assertEquals(2, report.historyStored)
        assertEquals(0, report.historyDuplicates)
        assertEquals(0, report.historySkipped)
        assertNull(report.historyError)
        assertArrayEquals(PLAINTEXT, sealer.open(h1.messageId, row(h1.messageId)!!.plaintextSealed!!))
        // One page sufficed (2 items < limit 20): no second fetch.
        assertEquals(1, pages)
        // Contiguous 1,2 with server at 0: cursor advances to 2.
        assertEquals(mapOf(CONV to 2L), report.cursorsAdvanced)
        assertEquals(2L, runBlocking { db.messageDao().conversation(CONV) }!!.cursorThrough)
        assertNull(report.cursorError)
    }

    @Test
    fun sweep_multiplePages_converge() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        runBlocking {
            db.messageDao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(CONV, 0L, 0L)
            )
        }
        val wires = (1..3).map { peerEncrypts(alice, bob) }
        val items = wires.mapIndexed { index, (wire, type) ->
            historyItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = (index + 1).toLong())
        }
        var pages = 0
        api.historyHandler = { _, after, limit ->
            pages++
            // Full pages force continuation; short page terminates.
            when (after) {
                0L -> items.take(limit)
                else -> items.dropWhile { it.sequenceNumber <= after }
            }
        }
        val report = runBlocking {
            sweep(SweepBounds(historyLimit = 2, historyMaxPages = 5)).sweep(session, server)
        }
        assertEquals(3, report.historyStored)
        assertEquals(2, pages)
        assertEquals(mapOf(CONV to 3L), report.cursorsAdvanced)
    }

    @Test
    fun sweep_historyDuplicate_absorbed_gapHoldsCursor() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        runBlocking {
            db.messageDao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(CONV, 0L, 0L)
            )
        }
        val (wire1, type1) = peerEncrypts(alice, bob)
        val (wire2, type2) = peerEncrypts(alice, bob)
        val (wire5, type5) = peerEncrypts(alice, bob)
        val h1 = historyItem(ALICE_DEVICE_ID, type1, wire1, sequenceNumber = 1L)
        val h2 = historyItem(ALICE_DEVICE_ID, type2, wire2, sequenceNumber = 2L)
        val h5 = historyItem(ALICE_DEVICE_ID, type5, wire5, sequenceNumber = 5L)
        api.historyHandler = { _, _, _ -> listOf(h1, h2, h5) }
        val first = runBlocking { sweep().sweep(session, server) }
        assertEquals(3, first.historyStored)
        // Short page (< limit) terminates the loop: no redundant fetch.
        assertEquals(0, first.historyDuplicates)
        assertEquals(0, first.historySkipped)
        // Gap at 3,4: cursor advances only through contiguous 2.
        assertEquals(mapOf(CONV to 2L), first.cursorsAdvanced)
        // Re-sweep: the short redelivery page resolves as duplicates.
        val second = runBlocking { sweep().sweep(session, server) }
        assertEquals(0, second.historyStored)
        assertEquals(3, second.historyDuplicates)
        assertEquals(emptyMap<String, Long>(), second.cursorsAdvanced)
        // Gap fill releases the cursor to 6 after seq 3,4,6 arrive.
        val (wire3, type3) = peerEncrypts(alice, bob)
        val (wire4, type4) = peerEncrypts(alice, bob)
        val (wire6, type6) = peerEncrypts(alice, bob)
        api.historyHandler = { _, after, _ ->
            when (after) {
                2L -> listOf(
                    historyItem(ALICE_DEVICE_ID, type3, wire3, sequenceNumber = 3L),
                    historyItem(ALICE_DEVICE_ID, type4, wire4, sequenceNumber = 4L),
                    historyItem(ALICE_DEVICE_ID, type6, wire6, sequenceNumber = 6L),
                )
                else -> emptyList()
            }
        }
        val third = runBlocking { sweep().sweep(session, server) }
        assertEquals(3, third.historyStored)
        assertEquals(mapOf(CONV to 6L), third.cursorsAdvanced)
        assertEquals(6L, runBlocking { dao().conversation(CONV) }!!.cursorThrough)
    }

    @Test
    fun sweep_malformedHistory_failsBranchWithoutWrites() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        runBlocking {
            db.messageDao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(CONV, 0L, 0L)
            )
        }
        api.historyHandler = { _, _, _ -> throw EnrollException.Malformed() }
        val report = runBlocking { sweep().sweep(session, server) }
        assertEquals("history-failed", report.historyError)
        assertEquals(0, report.historyStored)
        // Outbox/inbox branches still ran independently.
        assertNull(report.outboxError)
        assertTrue(report.inbox is InboxResult.Completed)
    }

    @Test
    fun sweep_cursorConflict_convergesLocalCache() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)) }
        api.getCursorHandler = { 10L }
        api.advanceHandler = { _, _ -> throw EnrollException.Conflict() }
        val report = runBlocking { sweep().sweep(session, server) }
        // Message processed; cursor PUT conflicted; cache converged.
        assertTrue(report.cursorsAdvanced.isEmpty())
        assertNull(report.cursorError)
        assertEquals(10L, runBlocking { dao().conversation(CONV) }!!.cursorThrough)
    }

    @Test
    fun sweep_cursorPutConflict_rereadsAndConverges() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        // Contiguous local state strictly ahead of the server cursor, but
        // the PUT loses a race: reread must converge, never force.
        val stored = { id: String, seq: Long ->
            com.samvaad.android.db.MessageEntity(
                messageId = id,
                conversationId = CONV,
                sequenceNumber = seq,
                direction = com.samvaad.android.db.MessageDirection.IN,
                senderDeviceId = ALICE_DEVICE_ID,
                recipientDeviceId = LOCAL_DEVICE_ID,
                envelopeType = "RATCHET",
                ciphertext = ByteArray(8) { seq.toByte() },
                plaintextSealed = sealer.seal(id, PLAINTEXT),
                sendState = null,
                acked = true,
                requestId = null,
                serverMessageId = id,
                serverTimestamp = "2026-10-02T10:00:00",
                createdAt = seq,
            )
        }
        runBlocking {
            dao().insertIgnore(stored("m-1", 1L))
            dao().insertIgnore(stored("m-2", 2L))
            dao().insertIgnore(stored("m-3", 3L))
        }
        api.getCursorHandler = { 0L }
        api.advanceHandler = { _, _ -> throw EnrollException.Conflict() }
        // Second read (post-conflict) reports the true server value.
        var reads = 0
        val realGet = api.getCursorHandler
        api.getCursorHandler = {
            reads++
            if (reads == 1) realGet(it) else 7L
        }
        val report = runBlocking { sweep().sweep(session, server) }
        assertTrue(report.cursorsAdvanced.isEmpty())
        assertNull(report.cursorError)
        assertEquals(7L, runBlocking { dao().conversation(CONV) }!!.cursorThrough)
    }

    @Test
    fun sweep_staleServerRead_neverRegressesCache() {
        // Cache claims 5 (e.g. from an earlier advance); the server read
        // comes back stale at 0. Contiguous local state is only 2.
        runBlocking {
            dao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(CONV, 5L, 0L)
            )
            dao().setCursor(CONV, 5L)
        }
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)) }
        api.getCursorHandler = { 0L }
        val report = runBlocking { sweep().sweep(session, server) }
        // No PUT (nothing past the cache), cache untouched at 5.
        assertTrue(api.advanceCalls.isEmpty())
        assertEquals(5L, runBlocking { dao().conversation(CONV) }!!.cursorThrough)
        assertNull(report.cursorError)
    }

    @Test
    fun sweep_cursorTransport_lagsWithoutLoss() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)) }
        api.advanceHandler = { _, _ -> throw EnrollException.Transport() }
        val report = runBlocking { sweep().sweep(session, server) }
        val completed = report.inbox as InboxResult.Completed
        assertEquals(1, completed.messages.size)
        assertEquals(1, completed.acked.size)
        assertEquals(0L, runBlocking { dao().conversation(CONV) }!!.cursorThrough)
        // Transport failure surfaces honestly on the cursor branch while
        // message state stays durable and ACKED.
        assertEquals("cursor-advance-failed", report.cursorError)
        // Retry converges once transport heals.
        api.advanceHandler = { _, through -> through }
        val retry = runBlocking { sweep().sweep(session, server) }
        assertEquals(mapOf(CONV to 1L), retry.cursorsAdvanced)
    }

    // ---- restart ----

    private fun fileSweep(
        fileDb: MessageDatabase,
        fileAdapter: AndroidSignalAdapter = AndroidSignalAdapter(),
    ) = ReconciliationSweep(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = fileAdapter,
        cryptoVault = cryptoVault,
        sessionVault = sessionVault,
        deviceLocks = SessionDeviceLocks(),
        db = fileDb,
        contentSealer = MessageContentSealer(keys),
    )

    @Test
    fun restart_sealedOutbound_resubmitsIdentically() {
        sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val fileDb = MessageDatabase.open(context)
        try {
            var failFirst = true
            api.submitHandler = { _, _ ->
                if (failFirst) {
                    failFirst = false
                    throw EnrollException.Transport()
                }
                api.okSubmitPublic(createdNew = false)
            }
            val sender = com.samvaad.android.session.MessageSender(
                api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault,
                SessionDeviceLocks(), fileDb, MessageContentSealer(keys),
            )
            val first = runBlocking {
                sender.send(session, server, ALICE_USERNAME, ALICE_DEVICE_ID, PLAINTEXT)
            }
            assertTrue(first is SendResult.Failed)
            val original = api.submits.single()
            fileDb.close()

            // Simulated restart: fresh adapter/sweep, same vaults/files.
            val reopened = MessageDatabase.open(context)
            try {
                val report = runBlocking { fileSweep(reopened).sweep(session, server) }
                val resubmitted = report.outboxRecovered.single() as RecoverOutcome.Resubmitted
                assertFalse(resubmitted.sent.createdNew)
                assertEquals(2, api.submits.size)
                assertEquals(original.first, api.submits[1].first)
                assertEquals(
                    original.second.single().ciphertextBase64,
                    api.submits[1].second.single().ciphertextBase64,
                )
            } finally {
                reopened.close()
            }
        } finally {
            if (fileDb.isOpen) fileDb.close()
        }
    }

    @Test
    fun restart_unackedInbound_convergesViaDuplicate() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, 2, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        var failAck = true
        api.ackHandler = { ids ->
            if (failAck) throw EnrollException.Transport()
            ids.size
        }
        val fileDb = MessageDatabase.open(context)
        try {
            val first = runBlocking { fileSweep(fileDb).sweep(session, server) }
            val completed = first.inbox as InboxResult.Completed
            assertEquals(1, completed.messages.size)
            assertEquals(listOf(item.messageId), completed.unacked)
            fileDb.close()

            // Simulated restart with healed ACK: redelivery hits the
            // duplicate path, ACKs, and marks — no second plaintext.
            failAck = false
            val reopened = MessageDatabase.open(context)
            try {
                val second = runBlocking { fileSweep(reopened).sweep(session, server) }
                val redelivered = second.inbox as InboxResult.Completed
                assertTrue(redelivered.messages.isEmpty())
                assertEquals(listOf(item.messageId), redelivered.acked)
                val dao = reopened.messageDao()
                assertEquals(true, runBlocking { dao.byMessageId(item.messageId) }!!.acked)
            } finally {
                reopened.close()
            }
        } finally {
            if (fileDb.isOpen) fileDb.close()
        }
    }
}
