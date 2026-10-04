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
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.ClaimedOneTimePrekey
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.InboxProcessor
import com.samvaad.android.session.InboxProcessor.RealtimeEntryResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import java.io.File
import java.io.IOException
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 13 realtime-ingest tests: single items through
 * [InboxProcessor.receiveOne] with REAL crypto (adapter + vault sealed
 * under an ephemeral AES key) and a scripted fake API. No network, no
 * UI, no STOMP socket: the socket/client layer is proven separately by
 * RealtimeInboxTest + RealtimeTlsInstrumentedTest.
 *
 * Every test asserts the same durable-before-ACK invariant as the
 * mailbox path: the fake ACK handler fails the test unless the durable
 * Room row already exists when ACK runs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class RealtimeIngestTest {

    companion object {
        val PLAINTEXT = "slice13-realtime-plaintext".toByteArray(Charsets.UTF_8)
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val ALICE_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val ALICE_USERNAME = "alice"
        const val ALICE_SIGNAL_ID = 2
        const val CONVERSATION_ID = "44444444-4444-4444-4444-444444444444"
    }

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null

        override fun getOrCreate(): SecretKey {
            return key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }
        }

        override fun getExisting(): SecretKey? = key
    }

    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: suspend (String, UUID) -> ClaimedDeviceBundle =
            { _, _ -> throw AssertionError("unexpected claim") }
        var ackHandler: suspend (List<UUID>) -> Int = { ids -> ids.size }
        var advanceHandler: suspend (String, Long) -> Long = { _, through -> through }
        var serverCursor: Long = 0L
        var directoryCalls = 0
        var claimCalls = 0
        var fetchCalls = 0
        val ackedBatches = mutableListOf<List<UUID>>()
        var fetchHandler: () -> List<MailboxItem> = { emptyList() }

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment here")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload here")

        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = throw AssertionError("no owner list here")

        override suspend fun approveDevice(
            session: AuthSession, serverAddress: String, deviceId: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no approval here")

        override suspend fun bindDevice(
            session: AuthSession, serverAddress: String, deviceId: String, recoveryCode: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no recovery here")

        override suspend fun recoverEnroll(
            session: AuthSession, serverAddress: String, recoveryCode: String,
            request: EnrollRequest,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no recovery here")

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
        ): SubmitMessageResult = throw AssertionError("no submit here")

        override suspend fun fetchMailbox(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<MailboxItem> {
            fetchCalls++
            return fetchHandler()
        }

        override suspend fun ackMailbox(
            session: AuthSession, serverAddress: String, messageIds: List<UUID>,
        ): Int {
            ackedBatches.add(messageIds.toList())
            return ackHandler(messageIds)
        }

        override suspend fun fetchHistory(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<com.samvaad.android.enroll.HistoryItem> =
            throw AssertionError("no history here")

        override suspend fun getSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
        ): com.samvaad.android.enroll.SyncCursor =
            com.samvaad.android.enroll.SyncCursor(conversationId, serverCursor)

        override suspend fun listConversations(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<String> = throw AssertionError("no conversation list here")

        override suspend fun uploadSyncBatch(
            session: AuthSession, serverAddress: String,
            request: com.samvaad.android.enroll.SyncUploadRequest,
        ): com.samvaad.android.enroll.SyncUploadResult =
            throw AssertionError("no history sync here")

        override suspend fun fetchSyncBatch(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<com.samvaad.android.enroll.SyncBatchItem> =
            throw AssertionError("no history sync here")

        override suspend fun ackSync(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncAckResult =
            throw AssertionError("no history sync here")

        override suspend fun advanceSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncCursor {
            val accepted = advanceHandler(conversationId, throughSequence)
            serverCursor = maxOf(serverCursor, accepted)
            return com.samvaad.android.enroll.SyncCursor(conversationId, accepted)
        }
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

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR).deleteRecursively()
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
        // Durable-before-ACK proof for every test: ACK must observe the
        // durable Room row, or the test fails right here.
        val inner = api.ackHandler
        api.ackHandler = { ids ->
            for (id in ids) {
                assertNotNull(
                    "ACK before durability for $id",
                    db.messageDao().byMessageId(id.toString()),
                )
            }
            inner(ids)
        }
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun processor() = InboxProcessor(
        api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault, locks, db, sealer,
    )

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
            ),
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

    private fun freshPeer(): PeerKeys {
        val peerAdapter = AndroidSignalAdapter()
        val identity = peerAdapter.generateIdentity()
        return PeerKeys(
            peerAdapter, ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001, identity,
            peerAdapter.generateSignedPrekey(identity, 11),
            peerAdapter.generateKyberPrekey(identity, 21),
            listOf(peerAdapter.generateOneTimePrekey(101)),
        )
    }

    /** Bob establishes outbound to the peer (creates the session entry). */
    private fun bobEstablishesTo(peer: PeerKeys) {
        val otk = peer.otpks.single()
        api.directoryHandler = {
            listOf(
                RecipientDeviceRecord(
                    deviceId = peer.deviceId,
                    registrationId = peer.regId,
                    signalDeviceId = peer.signalId,
                    deviceIdentityPublicKey = SpikeCryptoMaterial.encodeBase64(peer.identity.publicKey),
                    signedPrekeyId = peer.signed.prekeyId,
                    signedPrekey = SpikeCryptoMaterial.encodeBase64(peer.signed.publicKey),
                    signedPrekeySignature = SpikeCryptoMaterial.encodeBase64(peer.signed.signature),
                    hasAvailableOneTimePrekey = true,
                    deviceRole = "COMPANION",
                    kyberPrekeyId = peer.kyber.prekeyId,
                    kyberPrekey = SpikeCryptoMaterial.encodeBase64(peer.kyber.publicKey),
                    kyberPrekeySignature = SpikeCryptoMaterial.encodeBase64(peer.kyber.signature),
                ),
            )
        }
        api.claimHandler = { id, _ ->
            ClaimedDeviceBundle(
                deviceId = id,
                registrationId = peer.regId,
                signalDeviceId = peer.signalId,
                deviceIdentityPublicKey = SpikeCryptoMaterial.encodeBase64(peer.identity.publicKey),
                signedPrekeyId = peer.signed.prekeyId,
                signedPrekey = SpikeCryptoMaterial.encodeBase64(peer.signed.publicKey),
                signedPrekeySignature = SpikeCryptoMaterial.encodeBase64(peer.signed.signature),
                oneTimePrekey = ClaimedOneTimePrekey(otk.prekeyId, SpikeCryptoMaterial.encodeBase64(otk.publicKey)),
                deviceRole = "COMPANION",
                kyberPrekeyId = peer.kyber.prekeyId,
                kyberPrekey = SpikeCryptoMaterial.encodeBase64(peer.kyber.publicKey),
                kyberPrekeySignature = SpikeCryptoMaterial.encodeBase64(peer.kyber.signature),
            )
        }
        val establisher = SessionEstablisher(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault,
        )
        val result = runBlocking {
            establisher.establish(session, server, peer.username, peer.deviceId)
        }
        assertTrue(result is SessionEstablishResult.Established)
    }

    /** The peer encrypts to Bob's adopted bundle: genuine wire bytes. */
    private fun peerEncrypts(peer: PeerKeys, bob: LocalPublics): Pair<ByteArray, String> {
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
    ) = MailboxItem(
        messageId = messageId.toString(),
        conversationId = CONVERSATION_ID,
        sequenceNumber = 1L,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(ciphertext),
        serverTimestamp = "2026-10-04T10:00:00",
    )

    private fun durableRow(messageId: String) =
        runBlocking { db.messageDao().byMessageId(messageId) }

    // ---- realtime ingest ----

    @Test
    fun realtimeItem_decryptsSealsAndAcksThroughSamePipeline() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)

        val result = runBlocking { processor().receiveOne(session, server, item) }

        assertTrue(result is RealtimeEntryResult.Decrypted)
        assertEquals(item.messageId, (result as RealtimeEntryResult.Decrypted).messageId)
        assertNotNull(durableRow(item.messageId))
        assertEquals(listOf(listOf(UUID.fromString(item.messageId))), api.ackedBatches)
        // Zero discovery/claims/submits on the realtime path either.
        assertEquals(1, api.directoryCalls)
        assertEquals(1, api.claimCalls)
    }

    @Test
    fun realtimeDuplicate_convergesWithoutRedelivery() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)

        val first = runBlocking { processor().receiveOne(session, server, item) }
        val second = runBlocking { processor().receiveOne(session, server, item) }

        assertTrue(first is RealtimeEntryResult.Decrypted)
        assertTrue(second is RealtimeEntryResult.Duplicate)
        assertNotNull(durableRow(item.messageId))
        // Both deliveries ACK the same id; still exactly one durable row.
        assertEquals(2, api.ackedBatches.size)
    }

    @Test
    fun realtimeUnknownSender_skippedWithoutAck() {
        sealLocalDevice()
        val item = mailboxItem("99999999-9999-9999-9999-999999999999", "RATCHET", ByteArray(16))

        val result = runBlocking { processor().receiveOne(session, server, item) }

        assertTrue(result is RealtimeEntryResult.Skipped)
        assertEquals("unknown-sender", (result as RealtimeEntryResult.Skipped).reason)
        assertTrue(api.ackedBatches.isEmpty())
        assertNull(durableRow(item.messageId))
    }

    @Test
    fun realtimeMalformedEnvelope_skippedWithoutAck() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, _) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, "BOGUS-TYPE", wire)

        val result = runBlocking { processor().receiveOne(session, server, item) }

        assertTrue(result is RealtimeEntryResult.Skipped)
        assertTrue(api.ackedBatches.isEmpty())
        assertNull(durableRow(item.messageId))
    }

    @Test
    fun realtimeCorruptCiphertext_notAcked() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val corrupt = wire.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }
        val item = mailboxItem(ALICE_DEVICE_ID, type, corrupt)

        val result = runBlocking { processor().receiveOne(session, server, item) }

        // Decrypt failure never authorizes an ACK; the mailbox row stays
        // for redelivery/reconciliation.
        assertTrue(result is RealtimeEntryResult.Skipped)
        assertTrue(api.ackedBatches.isEmpty())
        assertNull(durableRow(item.messageId))
    }

    @Test
    fun realtimeRaceWithMailbox_convergesOnOneDurableRow() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)

        // Realtime wins the race; the sweep fetch then converges.
        val realtime = runBlocking { processor().receiveOne(session, server, item) }
        api.fetchHandler = { listOf(item) }
        val sweep = runBlocking { processor().receive(session, server, 20) }

        assertTrue(realtime is RealtimeEntryResult.Decrypted)
        val completed = sweep as com.samvaad.android.session.InboxResult.Completed
        assertEquals(listOf(item.messageId), completed.acked)
        assertTrue(completed.messages.isEmpty())
        assertNotNull(durableRow(item.messageId))
    }

    @Test
    fun realtimeAckFailure_recoversThroughMailboxRedelivery() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        val realAck = api.ackHandler
        api.ackHandler = { throw EnrollException.Transport(IOException("ack down")) }

        // Plaintext is delivered exactly once; the ACK failure surfaces
        // without losing durability.
        val realtime = runBlocking { processor().receiveOne(session, server, item) }
        assertTrue(realtime is RealtimeEntryResult.Failed)
        assertNotNull(durableRow(item.messageId))

        // Transport recovers: mailbox redelivery converges through the
        // duplicate path and ACKs without delivering again.
        api.ackHandler = realAck
        api.fetchHandler = { listOf(item) }
        val sweep = runBlocking { processor().receive(session, server, 20) }
        val completed = sweep as com.samvaad.android.session.InboxResult.Completed
        assertEquals(listOf(item.messageId), completed.acked)
        assertTrue(completed.messages.isEmpty())
    }

    @Test
    fun receiveDoesNotAckWithoutProcessing() {
        // Receiving a STOMP MESSAGE must never manufacture an ACK: only
        // the durable pipeline authorizes one. An empty mailbox fetch
        // therefore ACKs nothing even after realtime items exist.
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        runBlocking { processor().receiveOne(session, server, item) }

        val before = api.ackedBatches.size
        api.fetchHandler = { emptyList() }
        runBlocking { processor().receive(session, server, 20) }
        assertEquals(before, api.ackedBatches.size)
    }

    @Test
    fun realtimeItem_advancesCursorThroughExistingRules() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)

        runBlocking { processor().receiveOne(session, server, item) }

        // Sequence 1 ingested contiguously: cursor advanced exactly as the
        // mailbox path would advance it.
        assertTrue(api.serverCursor >= 1L)
    }

    @Test
    fun realtimeIsNotASweep_noFetchOccurs() {
        val bob = sealLocalDevice()
        val alice = freshPeer()
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)

        runBlocking { processor().receiveOne(session, server, mailboxItem(ALICE_DEVICE_ID, type, wire)) }

        // receiveOne ingests exactly one caller-supplied item: it never
        // fetches the mailbox (that stays the sweep's job).
        assertEquals(0, api.fetchCalls)
    }
}
