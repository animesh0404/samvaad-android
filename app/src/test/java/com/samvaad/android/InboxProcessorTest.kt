package com.samvaad.android

import android.content.Context
import androidx.room.InvalidationTracker
import androidx.sqlite.db.SupportSQLiteOpenHelper
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
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.InboxFailure
import com.samvaad.android.session.InboxProcessor
import com.samvaad.android.session.InboxResult
import com.samvaad.android.session.MessageSender
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Inbox-processor tests with a scripted fake API and REAL crypto
 * (adapter + vault sealed under an ephemeral AES key). No network, no UI.
 *
 * Peer devices are independent adapter instances with full private
 * material: they establish outbound to Bob's adopted public bundle and
 * encrypt, producing genuine wire ciphertext for the fake mailbox. Fake
 * counters prove zero discovery/claims on the receive path and exact ACK
 * behavior per outcome.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class InboxProcessorTest {

    companion object {
        val PLAINTEXT = "slice8-inbox-plaintext".toByteArray(Charsets.UTF_8)
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val ALICE_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val ALICE_USERNAME = "alice"
        const val ALICE_SIGNAL_ID = 2
    }

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null

        /** When true, seal-time key creation fails (read path unaffected). */
        var failCreate = false

        override fun getOrCreate(): SecretKey {
            if (failCreate) throw com.samvaad.android.crypto.VaultException.StorageFailure()
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
        var submitHandler: suspend (UUID, List<MessageEnvelopeSubmit>) -> SubmitMessageResult =
            { _, _ -> throw AssertionError("unexpected submit") }
        val submits = mutableListOf<Pair<UUID, List<MessageEnvelopeSubmit>>>()
        var fetchHandler: () -> List<MailboxItem> = { emptyList() }
        var ackHandler: suspend (List<UUID>) -> Int =
            { ids -> ids.size }
        var advanceHandler: suspend (String, Long) -> Long = { _, through -> through }
        var serverCursor: Long = 0L
        val advanceCalls = mutableListOf<Pair<String, Long>>()
        var directoryCalls = 0
        var claimCalls = 0
        var submitCalls = 0
        var fetchCalls = 0
        val ackedBatches = mutableListOf<List<UUID>>()

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
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<com.samvaad.android.enroll.HistoryItem> =
            throw AssertionError("no history in this slice")

        override suspend fun getSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
        ): com.samvaad.android.enroll.SyncCursor =
            com.samvaad.android.enroll.SyncCursor(conversationId, serverCursor)

        override suspend fun advanceSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncCursor {
            advanceCalls.add(conversationId to throughSequence)
            val accepted = advanceHandler(conversationId, throughSequence)
            serverCursor = maxOf(serverCursor, accepted)
            return com.samvaad.android.enroll.SyncCursor(conversationId, accepted)
        }
    }

    /** Bob's adopted public bundle, retained for peer establishment. */
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

    /** Peer device with full private material + retained publics. */
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

    private fun freshPeer(
        deviceId: String,
        username: String,
        signalId: Int,
        regId: Int,
        signedId: Int = 11,
        kyberId: Int = 21,
        otkId: Int = 101,
    ): PeerKeys {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return PeerKeys(
            adapter, deviceId, username, signalId, regId, identity,
            adapter.generateSignedPrekey(identity, signedId),
            adapter.generateKyberPrekey(identity, kyberId),
            listOf(adapter.generateOneTimePrekey(otkId)),
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

    private fun processor() = InboxProcessor(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = adapter,
        cryptoVault = cryptoVault,
        sessionVault = sessionVault,
        deviceLocks = locks,
        db = db,
        contentSealer = sealer,
    )

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
    }

    @After
    fun tearDown() {
        db.close()
    }

    /** Seal Bob's adopted device; retain publics for peer establishment. */
    private fun sealLocalDevice(): LocalPublics {
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..3).map { adapter.generateOneTimePrekey(5000 + it) }
        identityVaultSeal(identity, signed, kyber, otpks)
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

    private fun identityVaultSeal(
        identity: SpikeCryptoMaterial.Identity,
        signed: SpikeCryptoMaterial.SignedPrekey,
        kyber: SpikeCryptoMaterial.KyberPrekey,
        otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    ) {
        cryptoVault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        cryptoVault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        cryptoVault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            cryptoVault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
    }

    /** Bob establishes outbound to the peer (creates the session entry). */
    private fun bobEstablishesTo(peer: PeerKeys) {
        // Keep the peer's live wrappers; only public bytes cross the fake.
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
                )
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
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault
        )
        val result = runBlocking {
            establisher.establish(session, server, peer.username, peer.deviceId)
        }
        assertTrue(result is SessionEstablishResult.Established)
    }

    /**
     * The peer establishes outbound to Bob's adopted bundle and encrypts.
     * Returns wire bytes + observed envelope type.
     */
    private fun peerEncrypts(
        peer: PeerKeys,
        bob: LocalPublics,
        text: ByteArray = PLAINTEXT,
        bobOtkIndex: Int = 0,
    ): Pair<ByteArray, String> {
        val established = peer.adapter.establishOutboundSession(
            peer.identity, peer.regId, "bob",
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = SpikeCryptoMaterial.decodeBase64(bob.identityB64),
                signedPrekeyId = bob.signedId,
                signedPrekey = SpikeCryptoMaterial.decodeBase64(bob.signedB64),
                signedPrekeySignature = SpikeCryptoMaterial.decodeBase64(bob.signedSigB64),
                oneTimePrekeyId = bob.otkIds[bobOtkIndex],
                oneTimePrekey = SpikeCryptoMaterial.decodeBase64(bob.otkB64s[bobOtkIndex]),
                kyberPrekeyId = bob.kyberId,
                kyberPrekey = SpikeCryptoMaterial.decodeBase64(bob.kyberB64),
                kyberPrekeySignature = SpikeCryptoMaterial.decodeBase64(bob.kyberSigB64),
            ),
        )
        val encrypted = peer.adapter.encryptForSubmit(
            peer.identity, peer.regId,
            established.sessionBytes, SpikeCryptoMaterial.decodeBase64(bob.identityB64),
            "bob", 1, text,
        )
        // Keep the peer's advanced session for follow-up messages.
        peerSessions[peer.deviceId] = encrypted.postEncryptSessionBytes
        return encrypted.ciphertextBytes to encrypted.envelopeType
    }

    private val peerSessions = mutableMapOf<String, ByteArray>()

    private fun peerEncryptsAgain(
        peer: PeerKeys,
        bob: LocalPublics,
        text: ByteArray = PLAINTEXT,
    ): Pair<ByteArray, String> {
        val sessionBytes = peerSessions[peer.deviceId]
            ?: throw AssertionError("peer has no session yet")
        val encrypted = peer.adapter.encryptForSubmit(
            peer.identity, peer.regId,
            sessionBytes, SpikeCryptoMaterial.decodeBase64(bob.identityB64),
            "bob", 1, text,
        )
        peerSessions[peer.deviceId] = encrypted.postEncryptSessionBytes
        return encrypted.ciphertextBytes to encrypted.envelopeType
    }

    private fun mailboxItem(
        senderDeviceId: String,
        envelopeType: String,
        ciphertext: ByteArray,
        messageId: UUID = UUID.randomUUID(),
        sequenceNumber: Long = 1L,
    ) = MailboxItem(
        messageId = messageId.toString(),
        conversationId = "44444444-4444-4444-4444-444444444444",
        sequenceNumber = sequenceNumber,
        senderUserId = "55555555-5555-5555-5555-555555555555",
        senderDeviceId = senderDeviceId,
        envelopeType = envelopeType,
        ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(ciphertext),
        serverTimestamp = "2026-10-02T10:00:00",
    )

    private fun sessionBlob(deviceId: String): ByteArray = sessionVault.unseal(
        SessionEstablisher.sessionHandleFor(deviceId), CryptoRecordKind.SESSION
    )

    private fun sessionBlobFile(deviceId: String): File {
        val handle = SessionEstablisher.sessionHandleFor(deviceId)
        return File(
            File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR),
            "${CryptoRecordKind.SESSION.name}_${handle.id}.svlt",
        )
    }

    // ---- happy paths ----

    @Test
    fun prekeyReceive_decryptsSealsAndAcks() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        assertEquals("PREKEY_INIT", type)
        val directoryBefore = api.directoryCalls
        val claimsBefore = api.claimCalls
        val preBlob = sessionBlob(ALICE_DEVICE_ID)

        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        val result = runBlocking { processor().receive(session, server) }
        val completed = result as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, completed.messages.size)
        val message = completed.messages.single()
        assertArrayEquals(PLAINTEXT, message.plaintext)
        assertEquals("PREKEY_INIT", message.envelopeType)
        assertEquals(item.messageId, message.messageId)
        assertEquals(listOf(item.messageId), completed.acked)
        assertTrue(completed.skipped.isEmpty())
        // ACK carried exactly this messageId.
        assertEquals(listOf(listOf(UUID.fromString(item.messageId))), api.ackedBatches)
        // Zero discovery/claims/submits on the receive path.
        assertEquals(directoryBefore, api.directoryCalls)
        assertEquals(claimsBefore, api.claimCalls)
        assertEquals(0, api.submitCalls)
        // The sealed session advanced past the pre-receive state.
        assertFalse(preBlob.contentEquals(sessionBlob(ALICE_DEVICE_ID)))
        adapter.inspectSession(sessionBlob(ALICE_DEVICE_ID))
    }

    @Test
    fun ratchetReceive_fullPingPong() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        // Alice PREKEY → Bob receives (acknowledged both sides after reply).
        val (wire1, _) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, "PREKEY_INIT", wire1)) }
        val first = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, first.messages.size)

        // Bob replies outbound (shares locks with the processor).
        val sender = MessageSender(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault, locks, db, sealer
        )
        api.submitHandler = { _, _ ->
            com.samvaad.android.enroll.SubmitMessageResult(
                "33333333-3333-3333-3333-333333333333",
                "44444444-4444-4444-4444-444444444444",
                7L, "2026-10-02T10:00:00", listOf(ALICE_DEVICE_ID), true,
            )
        }
        val sent = runBlocking {
            sender.send(session, server, ALICE_USERNAME, ALICE_DEVICE_ID, PLAINTEXT)
        }
        assertTrue(sent is SendResult.Sent)
        // Alice decrypts Bob's reply through her RATCHET path…
        val replyB64 = api.submits.single().second.single().ciphertextBase64
        val aliceDecrypted = alice.adapter.decryptForInbox(
            localIdentity = alice.identity,
            localRegistrationId = alice.regId,
            signed = alice.signed,
            kyber = alice.kyber,
            otpks = alice.otpks,
            sessionBytes = peerSessions[ALICE_DEVICE_ID]!!,
            pinnedRemoteIdentity = SpikeCryptoMaterial.decodeBase64(bob.identityB64),
            remoteUsername = "bob",
            remoteSignalDeviceId = 1,
            envelopeType = "RATCHET",
            ciphertext = SpikeCryptoMaterial.decodeBase64(replyB64),
        )
        assertArrayEquals(PLAINTEXT, aliceDecrypted.plaintext)
        // …acknowledges her side, and answers RATCHET…
        peerSessions[ALICE_DEVICE_ID] = aliceDecrypted.postDecryptSessionBytes
        val (wire2, type2) = peerEncryptsAgain(alice, bob)
        assertEquals("RATCHET", type2)
        // …which Bob's processor decrypts as RATCHET.
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type2, wire2, sequenceNumber = 3L)) }
        val second = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, second.messages.size)
        assertArrayEquals(PLAINTEXT, second.messages.single().plaintext)
        assertEquals("RATCHET", second.messages.single().envelopeType)
        assertEquals(1, second.acked.size)
    }

    // ---- duplicate / failure invariants ----

    @Test
    fun duplicateDelivery_acksWithoutPlaintext() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        val p = processor()
        val first = runBlocking { p.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, first.messages.size)
        val blobAfterFirst = sessionBlob(ALICE_DEVICE_ID)

        // Same entry redelivered: duplicate proof authorizes the ACK.
        val second = runBlocking { p.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(second.messages.isEmpty())
        assertTrue(second.skipped.isEmpty())
        assertEquals(listOf(item.messageId), second.acked)
        // No session write happened on the duplicate path.
        assertArrayEquals(blobAfterFirst, sessionBlob(ALICE_DEVICE_ID))
        // The ACK went out twice (once per delivery), same messageId.
        assertEquals(2, api.ackedBatches.size)
    }

    @Test
    fun decryptFailure_skipsWithoutAck() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val tampered = wire.copyOf().also { it[it.size / 2] = it[it.size / 2].inc().toByte() }
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, tampered)) }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(result.messages.isEmpty())
        assertTrue(result.acked.isEmpty())
        assertEquals(1, result.skipped.size)
        assertEquals("decrypt-failed", result.skipped.single().reason)
        assertTrue(api.ackedBatches.isEmpty())
    }

    @Test
    fun persistFailure_skipsWithoutAck() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire)) }
        // Break SESSION seal-time key creation only: the content sealer
        // runs on independent keys so plaintext sealing still succeeds
        // and the failure lands exactly on the post-decrypt session seal.
        keys.failCreate = true
        val sealerOnOwnKeys = MessageContentSealer(EphemeralKeys())
        val proc = InboxProcessor(
            api = api,
            localMetadata = localMeta,
            sessions = sessionMeta,
            adapter = adapter,
            cryptoVault = cryptoVault,
            sessionVault = sessionVault,
            deviceLocks = locks,
            db = db,
            contentSealer = sealerOnOwnKeys,
        )
        try {
            val result = runBlocking { proc.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
            assertTrue(result.messages.isEmpty())
            assertTrue(result.acked.isEmpty())
            assertEquals("session-persist-failed", result.skipped.single().reason)
            assertTrue(api.ackedBatches.isEmpty())
        } finally {
            keys.failCreate = false
        }
    }

    @Test
    fun ackFailure_deliversOnce_acksOnRedelivery() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        var failAck = true
        api.ackHandler = { ids ->
            if (failAck) throw EnrollException.Transport()
            ids.size
        }
        val p = processor()
        val first = runBlocking { p.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        // Plaintext delivered exactly once despite the ACK failure.
        assertEquals(1, first.messages.size)
        assertArrayEquals(PLAINTEXT, first.messages.single().plaintext)
        assertTrue(first.acked.isEmpty())
        assertEquals(listOf(item.messageId), first.unacked)
        assertTrue(first.skipped.isEmpty())

        // Next fetch redelivers; the duplicate path authorizes the ACK.
        failAck = false
        val second = runBlocking { p.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(second.messages.isEmpty())
        assertEquals(listOf(item.messageId), second.acked)
    }

    @Test
    fun unknownSender_skipped_othersProceed() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val ghostId = "99999999-9999-9999-9999-999999999999"
        api.fetchHandler = {
            listOf(
                mailboxItem(ghostId, "PREKEY_INIT", wire),
                mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 2L),
            )
        }
        val claimsBefore = api.claimCalls
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, result.messages.size)
        assertEquals(1, result.skipped.size)
        assertEquals("unknown-sender", result.skipped.single().reason)
        // No discovery, no claims, no session created for the stranger.
        assertEquals(claimsBefore, api.claimCalls)
        assertEquals(ALICE_DEVICE_ID, result.messages.single().senderDeviceId)
        assertEquals(1, result.acked.size)
    }

    @Test
    fun malformedEntries_skipped() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        // Invalid Base64 must bypass the helper (which encodes): build the
        // item directly so the wire carries a non-alphabet body.
        val badB64 = MailboxItem(
            messageId = UUID.randomUUID().toString(),
            conversationId = "44444444-4444-4444-4444-444444444444",
            sequenceNumber = 9L,
            senderUserId = "55555555-5555-5555-5555-555555555555",
            senderDeviceId = ALICE_DEVICE_ID,
            envelopeType = "PREKEY_INIT",
            ciphertextBase64 = "!!!not-base64!!!",
            serverTimestamp = "2026-10-02T10:00:00",
        )
        api.fetchHandler = {
            listOf(
                mailboxItem(ALICE_DEVICE_ID, "CARRIER_PIGEON", PLAINTEXT),
                badB64,
            )
        }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(result.messages.isEmpty())
        assertTrue(result.acked.isEmpty())
        assertEquals(
            listOf("unsupported-envelope-type", "malformed-ciphertext"),
            result.skipped.map { it.reason },
        )
    }

    @Test
    fun pinMismatch_skippedWithoutAck() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val entry = sessionMeta.read(ALICE_DEVICE_ID)!!
        sessionMeta.write(entry.copy(remoteIdentityPublicKeyB64 = freshPeer("x", "x", 9, 9001).identity.let {
            SpikeCryptoMaterial.encodeBase64(it.publicKey)
        }))
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire)) }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(result.messages.isEmpty())
        assertTrue(result.acked.isEmpty())
        assertEquals("identity-mismatch", result.skipped.single().reason)
        assertTrue(api.ackedBatches.isEmpty())
    }

    @Test
    fun missingBlob_skippedWithoutAck() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        assertTrue(sessionBlobFile(ALICE_DEVICE_ID).delete())
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire)) }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(result.messages.isEmpty())
        assertEquals("session-blob-missing", result.skipped.single().reason)
        assertTrue(api.ackedBatches.isEmpty())
    }

    @Test
    fun fetchFailures_mapCorrectly() {
        sealLocalDevice()
        api.fetchHandler = { throw EnrollException.Unauthorized() }
        assertTrue(
            runBlocking { processor().receive(session, server) } ==
                com.samvaad.android.session.InboxResult.Failed(
                    com.samvaad.android.session.InboxFailure.Unauthorized
                )
        )
        api.fetchHandler = { throw EnrollException.Transport() }
        assertTrue(
            runBlocking { processor().receive(session, server) } ==
                com.samvaad.android.session.InboxResult.Failed(
                    com.samvaad.android.session.InboxFailure.TransportRetryable
                )
        )
        val bad = runBlocking { processor().receive(session, server, limit = 101) }
        assertTrue(bad is com.samvaad.android.session.InboxResult.Failed)
    }

    @Test
    fun concurrentSameSender_serializes() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire1, type1) = peerEncrypts(alice, bob)
        val (wire2, _) = peerEncryptsAgain(alice, bob)
        var atOnce = 0
        var maxAtOnce = 0
        api.ackHandler = { ids ->
            atOnce++
            maxAtOnce = maxOf(maxAtOnce, atOnce)
            delay(150)
            atOnce--
            ids.size
        }
        api.fetchHandler = {
            listOf(
                mailboxItem(
                    ALICE_DEVICE_ID, type1, wire1,
                    messageId = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                ),
                mailboxItem(
                    ALICE_DEVICE_ID, type1, wire2, sequenceNumber = 2L,
                    messageId = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                ),
            )
        }
        // Two overlapping receives: entries serialize per sender device.
        val p = processor()
        runBlocking {
            val a = async { p.receive(session, server) }
            val b = async { p.receive(session, server) }
            val ra = a.await() as com.samvaad.android.session.InboxResult.Completed
            val rb = b.await() as com.samvaad.android.session.InboxResult.Completed
            // Exactly one plaintext per entry across both receives: the
            // loser hits the duplicate path, never a second delivery.
            val delivered = (ra.messages + rb.messages).map { it.messageId }.sorted()
            assertEquals(
                listOf(
                    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                ),
                delivered,
            )
            // Every entry was ACKed by both receives (re-ACKs are
            // server-idempotent no-ops); plaintext delivered once each.
            assertEquals(4, ra.acked.size + rb.acked.size)
            assertTrue((ra.acked + rb.acked).containsAll(delivered))
        }
        adapter.inspectSession(sessionBlob(ALICE_DEVICE_ID))
    }

    @Test
    fun crossDirectionSendReceive_sharesOneLock() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire)) }
        api.submitHandler = { _, _ ->
            delay(150)
            SubmitMessageResult(
                "33333333-3333-3333-3333-333333333333",
                "44444444-4444-4444-4444-444444444444",
                9L, "2026-10-02T10:00:00", listOf(ALICE_DEVICE_ID), true,
            )
        }
        val sender = MessageSender(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault, locks, db, sealer
        )
        val inbox = processor()
        runBlocking {
            val sendJob = async {
                sender.send(session, server, ALICE_USERNAME, ALICE_DEVICE_ID, PLAINTEXT)
            }
            val receiveJob = async { inbox.receive(session, server) }
            val sendResult = sendJob.await()
            val receiveResult = receiveJob.await() as com.samvaad.android.session.InboxResult.Completed
            assertTrue(sendResult is SendResult.Sent)
            assertEquals(1, receiveResult.messages.size)
            assertArrayEquals(PLAINTEXT, receiveResult.messages.single().plaintext)
        }
        // Fork detector: a further round trip still decrypts on both ends.
        val followBlob = sessionBlob(ALICE_DEVICE_ID)
        adapter.inspectSession(followBlob)
        val (wire2, type2) = peerEncryptsAgain(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type2, wire2, sequenceNumber = 5L)) }
        val follow = runBlocking { inbox.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, follow.messages.size)
        assertArrayEquals(PLAINTEXT, follow.messages.single().plaintext)
    }

    @Test
    fun differentSenders_independent() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        val carol = freshPeer("cccccccc-cccc-cccc-cccc-cccccccccccc", "carol", 3, 7002)
        bobEstablishesTo(alice)
        bobEstablishesTo(carol)
        val (wireA, typeA) = peerEncrypts(alice, bob)
        val (wireC, typeC) = peerEncrypts(carol, bob)
        api.fetchHandler = {
            listOf(
                mailboxItem(ALICE_DEVICE_ID, typeA, wireA),
                mailboxItem(carol.deviceId, typeC, wireC, sequenceNumber = 2L),
            )
        }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(2, result.messages.size)
        assertArrayEquals(PLAINTEXT, result.messages[0].plaintext)
        assertArrayEquals(PLAINTEXT, result.messages[1].plaintext)
        assertEquals(2, result.acked.size)
        assertTrue(result.skipped.isEmpty())
    }

    // ---- Slice 9 Step 4: durable inbound state ----

    private fun dao() = db.messageDao()

    private fun inboxRow(messageId: String) = runBlocking { dao().byMessageId(messageId) }

    @Test
    fun receiveHappy_persistsRowSealsPlaintextAdvancesCursor() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)
        api.fetchHandler = { listOf(item) }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, result.messages.size)

        // Durable row keyed by the server messageId, acked, with exact bytes.
        val row = inboxRow(item.messageId)!!
        assertEquals(com.samvaad.android.db.MessageDirection.IN, row.direction)
        assertEquals(true, row.acked)
        assertEquals(null, row.sendState)
        assertEquals(null, row.requestId)
        assertEquals(null, row.serverMessageId)
        assertEquals(ALICE_DEVICE_ID, row.senderDeviceId)
        assertEquals(LOCAL_DEVICE_ID, row.recipientDeviceId)
        assertEquals(type, row.envelopeType)
        assertEquals(1L, row.sequenceNumber)
        assertArrayEquals(wire, row.ciphertext)
        // Sealed plaintext opens; no cleartext in the row.
        assertArrayEquals(PLAINTEXT, sealer.open(item.messageId, row.plaintextSealed!!))
        // Conversation observed + cursor advanced through contiguous 1.
        val conv = runBlocking { dao().conversation(item.conversationId) }!!
        assertEquals(1L, conv.lastSeenSequence)
        assertEquals(1L, conv.cursorThrough)
        assertEquals(listOf(item.conversationId to 1L), api.advanceCalls)
    }

    @Test
    fun noPlaintextInDatabaseFiles() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire)) }
        runBlocking { processor().receive(session, server) }
        db.close()
        // Reopen to checkpoint WAL, then scan every message-state file.
        val reopened = MessageDatabase.open(context)
        try {
            runBlocking { reopened.messageDao().byMessageId("absent") }
        } finally {
            reopened.close()
        }
        val dir = File(File(context.noBackupFilesDir, MessageDatabase.SUBDIR), "")
        val files = dir.listFiles()?.toList().orEmpty()
        assertTrue(files.isNotEmpty())
        files.forEach { file ->
            if (file.isFile) {
                assertFalse(
                    "cleartext in ${file.name}",
                    file.readBytes().toList().windowed(PLAINTEXT.size).any { it.toByteArray().contentEquals(PLAINTEXT) },
                )
            }
        }
    }

    @Test
    fun duplicateMessageId_absorbed_notOverwritten() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        // A stale row already claims this messageId with other bytes.
        val staleCipher = ByteArray(16) { 0x2B }
        val staleSealed = sealer.seal(item.messageId, "stale".toByteArray())
        runBlocking {
            dao().insertIgnore(
                com.samvaad.android.db.MessageEntity(
                    messageId = item.messageId,
                    conversationId = item.conversationId,
                    sequenceNumber = item.sequenceNumber,
                    direction = com.samvaad.android.db.MessageDirection.IN,
                    senderDeviceId = item.senderDeviceId,
                    recipientDeviceId = LOCAL_DEVICE_ID,
                    envelopeType = item.envelopeType,
                    ciphertext = staleCipher,
                    plaintextSealed = staleSealed,
                    sendState = null,
                    acked = false,
                    requestId = null,
                    serverMessageId = null,
                    serverTimestamp = item.serverTimestamp,
                    createdAt = 1L,
                )
            )
        }
        api.fetchHandler = { listOf(item) }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        // Recovery proceeds (fresh decrypt against current disk state),
        // delivers, and ACKs — but the durable bytes are never replaced.
        assertEquals(1, result.messages.size)
        assertArrayEquals(PLAINTEXT, result.messages.single().plaintext)
        val row = inboxRow(item.messageId)!!
        assertArrayEquals(staleCipher, row.ciphertext)
        assertArrayEquals(staleSealed, row.plaintextSealed)
    }

    @Test
    fun markAckFailure_convergesOnRedelivery() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        val item = mailboxItem(ALICE_DEVICE_ID, type, wire)
        api.fetchHandler = { listOf(item) }
        // Fail ONLY the local ACK flag: wrap the real DAO so every other
        // store operation behaves normally.
        val realDao = dao()
        var failMark = true
        val failingDb = object : MessageDatabase() {
            override fun messageDao(): com.samvaad.android.db.MessageDao =
                object : com.samvaad.android.db.MessageDao by realDao {
                    override suspend fun markAcked(messageId: String): Int {
                        if (failMark) throw android.database.sqlite.SQLiteException("injected")
                        return realDao.markAcked(messageId)
                    }
                }

            override fun createOpenHelper(config: androidx.room.DatabaseConfiguration):
                SupportSQLiteOpenHelper =
                throw AssertionError("never opened directly")

            override fun createInvalidationTracker(): InvalidationTracker =
                throw AssertionError("never opened directly")

            override fun clearAllTables() {
                throw AssertionError("never opened directly")
            }
        }
        val proc = InboxProcessor(
            api = api,
            localMetadata = localMeta,
            sessions = sessionMeta,
            adapter = adapter,
            cryptoVault = cryptoVault,
            sessionVault = sessionVault,
            deviceLocks = locks,
            db = failingDb,
            contentSealer = sealer,
        )
        val first = runBlocking { proc.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        // Plaintext delivered exactly once despite the ACK failure.
        assertEquals(1, first.messages.size)
        assertTrue(first.acked.isEmpty())
        assertEquals(listOf(item.messageId), first.unacked)
        assertEquals(false, inboxRow(item.messageId)!!.acked)

        // Next fetch redelivers; the duplicate path re-ACKs and the flag
        // converges without a second plaintext delivery.
        failMark = false
        val second = runBlocking { proc.receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertTrue(second.messages.isEmpty())
        assertEquals(listOf(item.messageId), second.acked)
        assertEquals(true, inboxRow(item.messageId)!!.acked)
    }

    @Test
    fun cursorHoldsAcrossGap_releasesOnFill() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val conv = "44444444-4444-4444-4444-444444444444"
        // History already holds 1,2,5 (5 arrived early, 3,4 missing).
        val stored = { id: String, seq: Long ->
            com.samvaad.android.db.MessageEntity(
                messageId = id,
                conversationId = conv,
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
            dao().insertIgnore(stored("m-5", 5L))
            dao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(conv, 5L, 2L)
            )
        }
        // A real seq-6 message arrives: contiguous stays 2, no advance.
        val (wire6, type6) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type6, wire6, sequenceNumber = 6L)) }
        val first = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, first.messages.size)
        assertTrue(api.advanceCalls.isEmpty())
        assertEquals(2L, runBlocking { dao().conversation(conv) }!!.cursorThrough)
        // Gap fills with real seq-3 and seq-4: contiguous becomes 6.
        val (wire3, type3) = peerEncryptsAgain(alice, bob)
        val (wire4, type4) = peerEncryptsAgain(alice, bob)
        api.fetchHandler = {
            listOf(
                mailboxItem(ALICE_DEVICE_ID, type3, wire3, sequenceNumber = 3L),
                mailboxItem(ALICE_DEVICE_ID, type4, wire4, sequenceNumber = 4L),
            )
        }
        val second = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(2, second.messages.size)
        // Contiguous advanced twice: 3 when the first gap closed, then 6.
        assertEquals(listOf(conv to 3L, conv to 6L), api.advanceCalls)
        assertEquals(6L, runBlocking { dao().conversation(conv) }!!.cursorThrough)
    }

    @Test
    fun cursorFailure_preservesMessage() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)) }
        api.advanceHandler = { _, _ -> throw EnrollException.Transport() }
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        // Message durable + ACKED; only the cursor lags.
        assertEquals(1, result.messages.size)
        assertEquals(1, result.acked.size)
        assertEquals(0L, runBlocking { dao().conversation("44444444-4444-4444-4444-444444444444") }!!.cursorThrough)
        // A later receive retries the advancement.
        api.advanceHandler = { _, through -> through }
        api.fetchHandler = { emptyList() }
        runBlocking { processor().receive(session, server) }
        // Empty batch performs no advancement by itself…
        assertEquals(0L, runBlocking { dao().conversation("44444444-4444-4444-4444-444444444444") }!!.cursorThrough)
    }

    @Test
    fun cursorConflict_convergesToServer() {
        val bob = sealLocalDevice()
        val alice = freshPeer(ALICE_DEVICE_ID, ALICE_USERNAME, ALICE_SIGNAL_ID, 7001)
        bobEstablishesTo(alice)
        val (wire, type) = peerEncrypts(alice, bob)
        api.fetchHandler = { listOf(mailboxItem(ALICE_DEVICE_ID, type, wire, sequenceNumber = 1L)) }
        api.advanceHandler = { _, _ -> throw EnrollException.Conflict() }
        api.serverCursor = 10L
        val result = runBlocking { processor().receive(session, server) } as com.samvaad.android.session.InboxResult.Completed
        assertEquals(1, result.messages.size)
        assertEquals(1, result.acked.size)
        // Server authoritative: local cache converges instead of forcing.
        assertEquals(10L, runBlocking { dao().conversation("44444444-4444-4444-4444-444444444444") }!!.cursorThrough)
    }
}
