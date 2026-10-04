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
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.ClaimedOneTimePrekey
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
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
import com.samvaad.android.enroll.SyncAckResult
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.enroll.SyncUploadRequest
import com.samvaad.android.enroll.SyncUploadResult
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.InboxProcessor
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.buildSyncPayload
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Sync-ingest tests against REAL crypto: the Companion resolves the
 * Primary session declared by the sync envelope (not the original
 * sender), decrypts, validates binding, and persists verbatim-original
 * rows. Unknown senders, binding mismatches, tampered payloads, and
 * duplicates all fail closed.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SyncIngestTest {

    companion object {
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val PRIMARY_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val USERNAME = "carol"
        const val CONVERSATION_ID = "44444444-4444-4444-4444-444444444444"
        const val MESSAGE_ID_1 = "11111111-1111-1111-1111-111111111111"
        const val MESSAGE_ID_2 = "22222222-1111-1111-1111-111111111111"
        const val OTHER_CONVERSATION_ID = "66666666-6666-6666-6666-666666666666"
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

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment in this test")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload in this test")

        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = throw AssertionError("no owner list in this test")

        override suspend fun approveDevice(
            session: AuthSession, serverAddress: String, deviceId: String,
        ): DeviceRecord = throw AssertionError("no approval in this test")

        override suspend fun bindDevice(
            session: AuthSession, serverAddress: String, deviceId: String, recoveryCode: String,
        ): DeviceRecord = throw AssertionError("no recovery in this test")

        override suspend fun recoverEnroll(
            session: AuthSession, serverAddress: String, recoveryCode: String,
            request: EnrollRequest,
        ): DeviceRecord = throw AssertionError("no recovery in this test")

        override suspend fun listRecipientDevices(
            session: AuthSession, serverAddress: String, username: String,
        ): List<RecipientDeviceRecord> = directoryHandler(username)

        override suspend fun claimOneTimePrekey(
            session: AuthSession, serverAddress: String, deviceId: String, requestId: UUID,
        ): ClaimedDeviceBundle = claimHandler(deviceId, requestId)

        override suspend fun submitMessage(
            session: AuthSession, serverAddress: String, requestId: UUID,
            envelopes: List<MessageEnvelopeSubmit>,
        ): SubmitMessageResult = throw AssertionError("no submit in this test")

        override suspend fun fetchMailbox(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<MailboxItem> = throw AssertionError("no mailbox in this test")

        override suspend fun ackMailbox(
            session: AuthSession, serverAddress: String, messageIds: List<UUID>,
        ): Int = throw AssertionError("no mailbox in this test")

        override suspend fun fetchHistory(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<HistoryItem> = throw AssertionError("no history in this test")

        override suspend fun getSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
        ): SyncCursor = throw AssertionError("no cursor in this test")

        override suspend fun advanceSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncCursor = throw AssertionError("no cursor in this test")

        override suspend fun listConversations(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<String> =
            throw AssertionError("no conversation list in this test")

        override suspend fun uploadSyncBatch(
            session: AuthSession, serverAddress: String, request: SyncUploadRequest,
        ): SyncUploadResult = throw AssertionError("no history sync in this test")

        override suspend fun fetchSyncBatch(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<SyncBatchItem> = throw AssertionError("no history sync in this test")

        override suspend fun ackSync(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncAckResult = throw AssertionError("no history sync in this test")
    }

    private data class PeerKeys(
        val adapter: AndroidSignalAdapter,
        val deviceId: String,
        val regId: Int,
        val signalId: Int,
        val identity: SpikeCryptoMaterial.Identity,
        val signed: SpikeCryptoMaterial.SignedPrekey,
        val kyber: SpikeCryptoMaterial.KyberPrekey,
        val otpks: List<SpikeCryptoMaterial.OneTimePrekey>,
    )

    private fun freshPeer(deviceId: String): PeerKeys {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        return PeerKeys(
            adapter, deviceId, 4141, 2, identity,
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
        identifier = USERNAME,
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
                roleHint = "COMPANION",
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

    private val peerSessions = mutableMapOf<String, ByteArray>()

    private fun establishTo(peer: PeerKeys) {
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
                    deviceRole = "PRIMARY",
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
                deviceRole = "PRIMARY",
                kyberPrekeyId = peer.kyber.prekeyId,
                kyberPrekey = SpikeCryptoMaterial.encodeBase64(peer.kyber.publicKey),
                kyberPrekeySignature = SpikeCryptoMaterial.encodeBase64(peer.kyber.signature),
            )
        }
        val establisher = SessionEstablisher(
            api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault
        )
        val result = runBlocking {
            establisher.establish(session, server, USERNAME, peer.deviceId)
        }
        assertTrue(result is SessionEstablishResult.Established)
    }

    private fun syncItem(
        peer: PeerKeys,
        local: LocalPublics,
        messageId: String,
        sequence: Long,
        text: String,
        frontier: Long,
        innerMessageId: String = messageId,
        innerSequence: Long = sequence,
        innerConversation: String = CONVERSATION_ID,
    ): SyncBatchItem {
        val payload = buildSyncPayload(
            conversationId = innerConversation,
            messageId = innerMessageId,
            sequenceNumber = innerSequence,
            senderDeviceId = "sender-a",
            recipientDeviceId = LOCAL_DEVICE_ID,
            serverTimestamp = "2026-10-03T10:00:00",
            plaintext = text.toByteArray(Charsets.UTF_8),
            frontier = frontier,
        )
        val sessionBytes = peerSessions[peer.deviceId] ?: peer.adapter.establishOutboundSession(
            peer.identity, peer.regId, USERNAME,
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = SpikeCryptoMaterial.decodeBase64(local.identityB64),
                signedPrekeyId = local.signedId,
                signedPrekey = SpikeCryptoMaterial.decodeBase64(local.signedB64),
                signedPrekeySignature = SpikeCryptoMaterial.decodeBase64(local.signedSigB64),
                oneTimePrekeyId = local.otkIds[0],
                oneTimePrekey = SpikeCryptoMaterial.decodeBase64(local.otkB64s[0]),
                kyberPrekeyId = local.kyberId,
                kyberPrekey = SpikeCryptoMaterial.decodeBase64(local.kyberB64),
                kyberPrekeySignature = SpikeCryptoMaterial.decodeBase64(local.kyberSigB64),
            ),
        ).sessionBytes
        val encrypted = peer.adapter.encryptForSubmit(
            peer.identity, peer.regId,
            sessionBytes,
            SpikeCryptoMaterial.decodeBase64(local.identityB64),
            USERNAME, 1, payload,
        )
        peerSessions[peer.deviceId] = encrypted.postEncryptSessionBytes
        return SyncBatchItem(
            messageId = messageId,
            conversationId = CONVERSATION_ID,
            sequenceNumber = sequence,
            senderDeviceId = peer.deviceId,
            envelopeType = encrypted.envelopeType,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(encrypted.ciphertextBytes),
        )
    }

    @Test
    fun storedRow_isVerbatimOriginal() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        val item = syncItem(primary, local, MESSAGE_ID_1, 1L, "hello-one", 1L)
        val result = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Stored)
        assertEquals(1L, (result as InboxProcessor.SyncIngestResult.Stored).frontier)
        val row = runBlocking { db.messageDao().byMessageId(MESSAGE_ID_1) }!!
        assertEquals(MessageDirection.IN, row.direction)
        assertEquals(true, row.acked)
        assertEquals(null, row.sendState)
        assertEquals(null, row.requestId)
        assertEquals(null, row.serverMessageId)
        assertEquals("sender-a", row.senderDeviceId)
        assertEquals(LOCAL_DEVICE_ID, row.recipientDeviceId)
        assertEquals(CONVERSATION_ID, row.conversationId)
        assertEquals(1L, row.sequenceNumber)
        assertEquals("2026-10-03T10:00:00", row.serverTimestamp)
        assertEquals("hello-one", sealer.open(MESSAGE_ID_1, row.plaintextSealed!!).toString(Charsets.UTF_8))
    }

    @Test
    fun unknownSyncSender_skipped() {
        sealLocalDevice()
        val item = SyncBatchItem(
            messageId = MESSAGE_ID_1,
            conversationId = CONVERSATION_ID,
            sequenceNumber = 1L,
            senderDeviceId = PRIMARY_DEVICE_ID,
            envelopeType = "RATCHET",
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64("eA==".toByteArray()),
        )
        val result = runBlocking {
            processor().ingestSyncItem(item, "99999999-9999-9999-9999-999999999999")
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Skipped)
        assertNull(runBlocking { db.messageDao().byMessageId(MESSAGE_ID_1) })
    }

    @Test
    fun bindingMismatch_skipped() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        val item = syncItem(primary, local, "33333333-1111-1111-1111-111111111111", 1L, "hello", 1L,
            innerMessageId = "44444444-1111-1111-1111-111111111111")
        val result = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Skipped)
        assertNull(runBlocking { db.messageDao().byMessageId("33333333-1111-1111-1111-111111111111") })
        assertNull(runBlocking { db.messageDao().byMessageId("44444444-1111-1111-1111-111111111111") })
    }

    @Test
    fun wrongConversation_skipped() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        val item = syncItem(primary, local, MESSAGE_ID_1, 1L, "hello", 1L,
            innerConversation = OTHER_CONVERSATION_ID)
        val result = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Skipped)
        assertNull(runBlocking { db.messageDao().byMessageId(MESSAGE_ID_1) })
    }

    @Test
    fun exactRedelivery_absorbedAsDuplicate() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        val item = syncItem(primary, local, MESSAGE_ID_1, 1L, "hello-one", 1L)
        val first = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(first is InboxProcessor.SyncIngestResult.Stored)
        val second = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(second is InboxProcessor.SyncIngestResult.Duplicate)
    }

    @Test
    fun sameIdDifferentBytes_keepsFirst() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        val first = runBlocking {
            processor().ingestSyncItem(
                syncItem(primary, local, MESSAGE_ID_1, 1L, "hello-one", 1L), PRIMARY_DEVICE_ID
            )
        }
        assertTrue(first is InboxProcessor.SyncIngestResult.Stored)
        // Same messageId, freshly encrypted (different bytes): the
        // server must never send this (409 on conflict), but absorption
        // keeps the first durable row rather than forking state.
        val second = runBlocking {
            processor().ingestSyncItem(
                syncItem(primary, local, MESSAGE_ID_1, 1L, "hello-two", 1L), PRIMARY_DEVICE_ID
            )
        }
        assertTrue(second is InboxProcessor.SyncIngestResult.Stored)
        val row = runBlocking { db.messageDao().byMessageId(MESSAGE_ID_1) }!!
        assertEquals("hello-one", sealer.open(MESSAGE_ID_1, row.plaintextSealed!!).toString(Charsets.UTF_8))
    }

    @Test
    fun malformedPayload_skipped() {
        val local = sealLocalDevice()
        val primary = freshPeer(PRIMARY_DEVICE_ID)
        establishTo(primary)
        // Valid Signal encryption of non-payload bytes: decrypts, then
        // fails payload validation fail-closed.
        val sessionBytes = peerSessions[primary.deviceId] ?: primary.adapter.establishOutboundSession(
            primary.identity, primary.regId, USERNAME,
            RemotePrekeyBundle(
                registrationId = 4242,
                signalDeviceId = 1,
                identityKey = SpikeCryptoMaterial.decodeBase64(local.identityB64),
                signedPrekeyId = local.signedId,
                signedPrekey = SpikeCryptoMaterial.decodeBase64(local.signedB64),
                signedPrekeySignature = SpikeCryptoMaterial.decodeBase64(local.signedSigB64),
                oneTimePrekeyId = local.otkIds[0],
                oneTimePrekey = SpikeCryptoMaterial.decodeBase64(local.otkB64s[0]),
                kyberPrekeyId = local.kyberId,
                kyberPrekey = SpikeCryptoMaterial.decodeBase64(local.kyberB64),
                kyberPrekeySignature = SpikeCryptoMaterial.decodeBase64(local.kyberSigB64),
            ),
        ).sessionBytes
        val encrypted = primary.adapter.encryptForSubmit(
            primary.identity, primary.regId,
            sessionBytes,
            SpikeCryptoMaterial.decodeBase64(local.identityB64),
            USERNAME, 1, "not-json".toByteArray(Charsets.UTF_8),
        )
        val item = SyncBatchItem(
            messageId = "m-1",
            conversationId = CONVERSATION_ID,
            sequenceNumber = 1L,
            senderDeviceId = PRIMARY_DEVICE_ID,
            envelopeType = encrypted.envelopeType,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(encrypted.ciphertextBytes),
        )
        val result = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Skipped)
        assertNull(runBlocking { db.messageDao().byMessageId("m-1") })
    }

    @Test
    fun unsupportedEnvelope_skipped() {
        sealLocalDevice()
        val item = SyncBatchItem(
            messageId = "m-1",
            conversationId = CONVERSATION_ID,
            sequenceNumber = 1L,
            senderDeviceId = PRIMARY_DEVICE_ID,
            envelopeType = "BOGUS",
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64("eA==".toByteArray()),
        )
        val result = runBlocking {
            processor().ingestSyncItem(item, PRIMARY_DEVICE_ID)
        }
        assertTrue(result is InboxProcessor.SyncIngestResult.Skipped)
    }
}
