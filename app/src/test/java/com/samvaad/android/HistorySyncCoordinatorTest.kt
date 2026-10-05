package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
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
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.FileSyncMetadataStore
import com.samvaad.android.session.HistorySyncCoordinator
import com.samvaad.android.session.HistorySyncReport
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SyncBounds
import com.samvaad.android.session.buildSyncPayload
import java.io.File
import java.io.IOException
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
 * History-sync coordinator tests with a scripted fake API and REAL
 * crypto/database (adapter + vaults sealed under an ephemeral AES key,
 * in-memory Room). No network, no UI. Export runs as PRIMARY, import
 * as COMPANION, both gated by live server device state.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HistorySyncCoordinatorTest {

    companion object {
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val PEER_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
        const val PEER_DEVICE_ID_2 = "33333333-3333-3333-3333-333333333333"
        const val USERNAME = "carol"
        const val CONVERSATION_ID = "44444444-4444-4444-4444-444444444444"
        const val CONVERSATION_ID_2 = "55555555-5555-5555-5555-555555555555"
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
        var devicesHandler: () -> DeviceList = {
            throw AssertionError("unexpected listDevices")
        }
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: suspend (String, UUID) -> ClaimedDeviceBundle =
            { _, _ -> throw AssertionError("unexpected claim") }
        var uploadHandler: suspend (SyncUploadRequest) -> SyncUploadResult =
            { throw AssertionError("unexpected upload") }
        var fetchHandler: suspend (String, Long, Int) -> List<SyncBatchItem> =
            { _, _, _ -> emptyList() }
        var ackHandler: suspend (String, Long) -> Int = { _, _ -> 0 }
        var conversationsHandler: () -> List<String> = { emptyList() }
        val uploads = mutableListOf<SyncUploadRequest>()
        val acks = mutableListOf<Pair<String, Long>>()
        var listCalls = 0
        var uploadCalls = 0

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment in this test")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload in this test")

        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = devicesHandler()

        override suspend fun approveDevice(
            session: AuthSession, serverAddress: String, deviceId: String,
        ): DeviceRecord = throw AssertionError("no approval in this test")

        override suspend fun bindDevice(
            session: AuthSession, serverAddress: String, deviceId: String, recoveryCode: String,
        ): DeviceRecord = throw AssertionError("no recovery in this test")

        override suspend fun beginAttach(
            session: AuthSession, serverAddress: String, deviceId: String,
        ): com.samvaad.android.enroll.AttachBegin =
            throw AssertionError("no attach in this test")

        override suspend fun completeAttach(
            session: AuthSession, serverAddress: String, deviceId: String,
            challengeId: String, proofBase64: String,
        ): com.samvaad.android.enroll.DeviceRecord =
            throw AssertionError("no attach in this test")

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
        ): List<String> = conversationsHandler()

        override suspend fun uploadSyncBatch(
            session: AuthSession, serverAddress: String, request: SyncUploadRequest,
        ): SyncUploadResult {
            uploadCalls++
            uploads.add(request)
            return uploadHandler(request)
        }

        override suspend fun fetchSyncBatch(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<SyncBatchItem> = fetchHandler(conversationId, afterSequence, limit)

        override suspend fun ackSync(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncAckResult {
            acks.add(conversationId to throughSequence)
            return SyncAckResult(ackHandler(conversationId, throughSequence))
        }
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
    ): PeerKeys {
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
    private lateinit var syncMeta: FileSyncMetadataStore
    private lateinit var locks: SessionDeviceLocks
    private lateinit var db: MessageDatabase
    private lateinit var sealer: MessageContentSealer
    private lateinit var establisher: SessionEstablisher

    private val session = AuthSession(
        identifier = USERNAME,
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private fun coordinator(bounds: SyncBounds = SyncBounds()) = HistorySyncCoordinator(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = adapter,
        identityVault = cryptoVault,
        sessionVault = sessionVault,
        establisher = establisher,
        deviceLocks = locks,
        db = db,
        contentSealer = sealer,
        syncMetadata = syncMeta,
        bounds = bounds,
    )

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, FileSyncMetadataStore.SUBDIR).deleteRecursively()
        api = FakeApi()
        keys = EphemeralKeys()
        adapter = AndroidSignalAdapter()
        cryptoVault = AndroidCryptoVault(context, keys)
        sessionVault = AndroidCryptoVault(context, keys, FileSessionMetadataStore.SUBDIR)
        localMeta = FileDeviceMetadataStore(context)
        sessionMeta = FileSessionMetadataStore(context)
        syncMeta = FileSyncMetadataStore(context)
        locks = SessionDeviceLocks()
        db = androidx.room.Room.inMemoryDatabaseBuilder(context, MessageDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        sealer = MessageContentSealer(keys)
        establisher = SessionEstablisher(api, localMeta, sessionMeta, adapter, cryptoVault, sessionVault)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun sealLocalDevice(roleHint: String = "PRIMARY"): LocalPublics {
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
                roleHint = roleHint,
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

    private fun deviceRow(deviceId: String, role: String, status: String = "ACTIVE") = DeviceRecord(
        deviceId = deviceId,
        registrationId = 4242,
        signalDeviceId = 2,
        deviceIdentityPublicKey = "a2V5",
        signedPrekeyId = 11,
        deviceRole = role,
        status = status,
        availablePrekeys = 3,
    )

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
        val result = runBlocking {
            establisher.establish(session, server, USERNAME, peer.deviceId)
        }
        assertTrue(result is SessionEstablishResult.Established)
    }

    private fun seedHistory(conversationId: String, vararg specs: Triple<Long, String, String>) {
        runBlocking {
            val dao = db.messageDao()
            dao.upsertConversation(ConversationEntity(conversationId, 0L, 0L))
            for ((sequence, text, sender) in specs) {
                val messageId = UUID.nameUUIDFromBytes("$conversationId-$sequence".toByteArray()).toString()
                dao.insertIgnore(
                    MessageEntity(
                        messageId = messageId,
                        conversationId = conversationId,
                        sequenceNumber = sequence,
                        direction = MessageDirection.IN,
                        senderDeviceId = sender,
                        recipientDeviceId = LOCAL_DEVICE_ID,
                        envelopeType = "RATCHET",
                        ciphertext = "Y3Q=".toByteArray(),
                        plaintextSealed = sealer.seal(messageId, text.toByteArray(Charsets.UTF_8)),
                        sendState = null,
                        acked = true,
                        requestId = null,
                        serverMessageId = "srv-$sequence",
                        serverTimestamp = "2026-10-03T10:00:00",
                        createdAt = System.currentTimeMillis(),
                    )
                )
            }
        }
    }

    // ---- role gating ----

    @Test
    fun primaryRole_exportsOrderedRowsWithFrontier() {
        sealLocalDevice("PRIMARY")
        val peer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(peer)
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(
                    deviceRow(LOCAL_DEVICE_ID, "PRIMARY"),
                    deviceRow(PEER_DEVICE_ID, "COMPANION"),
                )
            )
        }
        seedHistory(
            CONVERSATION_ID,
            Triple(1L, "secret-one", "sender-a"),
            Triple(2L, "secret-two", "sender-a"),
            Triple(3L, "secret-three", "sender-b"),
        )
        api.uploadHandler = { request ->
            SyncUploadResult(request.syncBatchId, request.items.size, true)
        }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertEquals(null, report.error)
        assertEquals(3, report.exportedItems)
        assertEquals(1, api.uploads.size)
        val uploaded = api.uploads.single()
        assertEquals(listOf(1L, 2L, 3L), uploaded.items.map { it.sequenceNumber })
        assertEquals(3L, uploaded.frontier)
        assertEquals(0L, uploaded.fromSequence)
        assertEquals(PEER_DEVICE_ID, uploaded.recipientDeviceId)
        assertEquals(LOCAL_DEVICE_ID, uploaded.items.single { it.sequenceNumber == 1L }.senderDeviceId)
        // Sealed plaintext never appears as plaintext in the upload path inputs.
        val dao = runBlocking { db.messageDao() }
        val row = runBlocking { dao.byMessageId(
            UUID.nameUUIDFromBytes("$CONVERSATION_ID-1".toByteArray()).toString()
        ) }!!
        assertTrue(row.plaintextSealed != null && !row.plaintextSealed.contentEquals("secret-one".toByteArray()))
    }

    @Test
    fun transportFailure_retriesSameBatchIdOnce() {
        sealLocalDevice("PRIMARY")
        val peer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(peer)
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRow(LOCAL_DEVICE_ID, "PRIMARY"), deviceRow(PEER_DEVICE_ID, "COMPANION"))
            )
        }
        seedHistory(CONVERSATION_ID, Triple(1L, "secret-one", "sender-a"))
        var calls = 0
        api.uploadHandler = { request ->
            calls++
            if (calls == 1) throw EnrollException.Transport()
            SyncUploadResult(request.syncBatchId, request.items.size, true)
        }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertEquals(null, report.error)
        assertEquals(2, api.uploadCalls)
        assertEquals(
            api.uploads[0].syncBatchId,
            api.uploads[1].syncBatchId
        )
    }

    @Test
    fun conflict_surfacesWithoutRetry() {
        sealLocalDevice("PRIMARY")
        val peer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(peer)
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRow(LOCAL_DEVICE_ID, "PRIMARY"), deviceRow(PEER_DEVICE_ID, "COMPANION"))
            )
        }
        seedHistory(CONVERSATION_ID, Triple(1L, "secret-one", "sender-a"))
        var calls = 0
        api.uploadHandler = {
            calls++
            throw EnrollException.Conflict()
        }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertTrue(report.error != null)
        assertEquals(1, calls)
    }

    @Test
    fun nonPrimaryRole_isSilentNoOp() {
        sealLocalDevice("PENDING")
        api.devicesHandler = {
            DeviceList(
                "RECOVERY_REQUIRED",
                listOf(deviceRow(LOCAL_DEVICE_ID, "PENDING", "PENDING"))
            )
        }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertEquals(null, report.error)
        assertEquals(0, report.exportedItems)
        assertEquals(0, api.uploadCalls)
    }

    @Test
    fun serverRoleWinsOverLocalHint() {
        // Adopted hint says PRIMARY, but the server says COMPANION:
        // the server truth drives an import run, not an export.
        sealLocalDevice("PRIMARY")
        val peer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(peer)
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRow(LOCAL_DEVICE_ID, "COMPANION"), deviceRow(PEER_DEVICE_ID, "PRIMARY"))
            )
        }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertEquals(0, report.exportedItems)
        assertEquals(0, api.uploadCalls)
    }

    // ---- import ----

    private val peerSessions = mutableMapOf<String, ByteArray>()

    private fun peerEncryptsToLocal(
        peer: PeerKeys,
        local: LocalPublics,
        payload: ByteArray,
    ): Pair<ByteArray, String> {
        val existing = peerSessions[peer.deviceId]
        val sessionBytes = existing ?: peer.adapter.establishOutboundSession(
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
        return encrypted.ciphertextBytes to encrypted.envelopeType
    }

    private fun syncItem(
        peer: PeerKeys,
        local: LocalPublics,
        conversationId: String,
        messageId: String,
        sequence: Long,
        text: String,
        frontier: Long,
        sender: String = "sender-a",
    ): SyncBatchItem {
        val payload = buildSyncPayload(
            conversationId = conversationId,
            messageId = messageId,
            sequenceNumber = sequence,
            senderDeviceId = sender,
            recipientDeviceId = LOCAL_DEVICE_ID,
            serverTimestamp = "2026-10-03T10:00:00",
            plaintext = text.toByteArray(Charsets.UTF_8),
            frontier = frontier,
        )
        val (bytes, type) = peerEncryptsToLocal(peer, local, payload)
        return SyncBatchItem(
            messageId = messageId,
            conversationId = conversationId,
            sequenceNumber = sequence,
            senderDeviceId = peer.deviceId,
            envelopeType = type,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(bytes),
        )
    }

    private fun companionDevices(primaryPeer: PeerKeys) {
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(
                    deviceRow(LOCAL_DEVICE_ID, "COMPANION"),
                    DeviceRecord(
                        deviceId = primaryPeer.deviceId,
                        registrationId = primaryPeer.regId,
                        signalDeviceId = primaryPeer.signalId,
                        deviceIdentityPublicKey = SpikeCryptoMaterial.encodeBase64(primaryPeer.identity.publicKey),
                        signedPrekeyId = primaryPeer.signed.prekeyId,
                        deviceRole = "PRIMARY",
                        status = "ACTIVE",
                        availablePrekeys = 3,
                    ),
                )
            )
        }
    }

    @Test
    fun companionImport_fullLoop_storesAckAndFrontier() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        val items = listOf(
            syncItem(primaryPeer, local, CONVERSATION_ID, "11111111-1111-1111-1111-111111111111", 1L, "hello-one", 2L),
            syncItem(primaryPeer, local, CONVERSATION_ID, "22222222-1111-1111-1111-111111111111", 2L, "hello-two", 2L),
        )
        api.fetchHandler = { _, _, _ -> items }
        var ackedTo = -1L
        api.ackHandler = { _, through -> ackedTo = through; 2 }
        val report = runBlocking {
            coordinator().sync(session, server, USERNAME)
        }
        assertEquals(null, report.error)
        assertEquals(2, report.importedStored)
        assertEquals(2L, ackedTo)
        assertEquals(2L, syncMeta.readFrontier(CONVERSATION_ID))
        val rows = runBlocking { db.messageDao() }
        val first = runBlocking { rows.byMessageId("11111111-1111-1111-1111-111111111111") }!!
        assertEquals(com.samvaad.android.db.MessageDirection.IN, first.direction)
        assertEquals(true, first.acked)
        assertEquals(null, first.sendState)
        assertEquals(null, first.requestId)
        assertEquals(null, first.serverMessageId)
        assertEquals("sender-a", first.senderDeviceId)
        assertEquals(LOCAL_DEVICE_ID, first.recipientDeviceId)
        assertEquals("2026-10-03T10:00:00", first.serverTimestamp)
        val opened = sealer.open("11111111-1111-1111-1111-111111111111", first.plaintextSealed!!).toString(Charsets.UTF_8)
        assertEquals("hello-one", opened)
    }

    @Test
    fun companionImport_duplicateConvergesAndAcks() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        val items = listOf(
            syncItem(primaryPeer, local, CONVERSATION_ID, "11111111-1111-1111-1111-111111111111", 1L, "hello-one", 1L),
        )
        api.fetchHandler = { _, _, _ -> items }
        val first = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, first.importedStored)
        val second = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, second.importedDuplicates)
        assertEquals(0, second.importedStored)
        assertEquals(2, api.acks.size)
        assertEquals(1L, api.acks.last().second)
    }

    @Test
    fun companionImport_gapBlocksAckBeyondGap() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        val items = listOf(
            syncItem(primaryPeer, local, CONVERSATION_ID, "11111111-1111-1111-1111-111111111111", 1L, "hello-one", 3L),
            syncItem(primaryPeer, local, CONVERSATION_ID, "33333333-1111-1111-1111-111111111111", 3L, "hello-three", 3L),
        )
        api.fetchHandler = { _, _, _ -> items }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(2, report.importedStored)
        assertEquals(1, api.acks.size)
        assertEquals(1L, api.acks.single().second)
    }

    @Test
    fun companionImport_bindingMismatch_skipped() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        // Wire messageId differs from the encrypted payload's: fail closed.
        val payload = buildSyncPayload(
            conversationId = CONVERSATION_ID,
            messageId = "55555555-1111-1111-1111-111111111111",
            sequenceNumber = 1L,
            senderDeviceId = "sender-a",
            recipientDeviceId = LOCAL_DEVICE_ID,
            serverTimestamp = "2026-10-03T10:00:00",
            plaintext = "x".toByteArray(Charsets.UTF_8),
            frontier = 1L,
        )
        val (bytes, type) = peerEncryptsToLocal(primaryPeer, local, payload)
        api.fetchHandler = { _, _, _ ->
            listOf(
                SyncBatchItem(
                    messageId = "44444444-1111-1111-1111-111111111111",
                    conversationId = CONVERSATION_ID,
                    sequenceNumber = 1L,
                    senderDeviceId = PEER_DEVICE_ID,
                    envelopeType = type,
                    ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(bytes),
                )
            )
        }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, report.importedSkipped)
        assertEquals(0, report.importedStored)
        assertTrue(api.acks.isEmpty())
    }

    @Test
    fun companionImport_frontierRegression_surfaced() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        syncMeta.writeFrontier(CONVERSATION_ID, 10L)
        api.fetchHandler = { _, _, _ ->
            listOf(syncItem(primaryPeer, local, CONVERSATION_ID, "11111111-1111-1111-1111-111111111111", 1L, "hello-one", 3L))
        }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, report.importedStored)
        assertTrue(report.error != null)
        assertEquals(10L, syncMeta.readFrontier(CONVERSATION_ID))
    }

    @Test
    fun companionImport_noPrimary_aborts() {
        sealLocalDevice("COMPANION")
        api.devicesHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(deviceRow(LOCAL_DEVICE_ID, "COMPANION")))
        }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertTrue(report.error != null)
        assertEquals(0, report.importedStored)
    }

    @Test
    fun companionImport_discoversConversationsFromServer() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        // No local rows at all: discovery comes from the server list.
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        api.fetchHandler = { _, _, _ ->
            listOf(syncItem(
                primaryPeer, local, CONVERSATION_ID,
                "99999999-1111-1111-1111-111111111111", 9L, "hello-nine", 9L,
            ))
        }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(null, report.error)
        assertEquals(1, report.importedStored)
        assertTrue(runBlocking {
            db.messageDao().byMessageId("99999999-1111-1111-1111-111111111111")
        } != null)
    }

    @Test
    fun companionImport_revokedDevice_silent() {
        sealLocalDevice("COMPANION")
        api.devicesHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRow(LOCAL_DEVICE_ID, "COMPANION", "REVOKED"))
            )
        }
        val report = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(null, report.error)
        assertEquals(0, report.importedStored)
    }

    @Test
    fun companionImport_crashBeforeAck_converges() {
        val local = sealLocalDevice("COMPANION")
        val primaryPeer = freshPeer(PEER_DEVICE_ID, USERNAME, 2, 4141)
        establishTo(primaryPeer)
        companionDevices(primaryPeer)
        api.conversationsHandler = { listOf(CONVERSATION_ID) }
        api.fetchHandler = { _, _, _ ->
            listOf(syncItem(primaryPeer, local, CONVERSATION_ID, "11111111-1111-1111-1111-111111111111", 1L, "hello-one", 1L))
        }
        var ackCalls = 0
        api.ackHandler = { _, _ ->
            ackCalls++
            if (ackCalls == 1) throw EnrollException.Transport()
            1
        }
        val first = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, first.importedStored)
        assertTrue(first.error != null)
        // Second run re-fetches freshly encrypted bytes for the same
        // message: absorption keeps the first durable row (no fork),
        // and the pending ACK converges.
        val second = runBlocking { coordinator().sync(session, server, USERNAME) }
        assertEquals(1, second.importedStored)
        assertEquals(0, second.importedDuplicates)
        assertEquals(null, second.error)
        assertEquals(2, api.acks.size)
        assertEquals(
            1,
            runBlocking { db.messageDao().sequencesFor(CONVERSATION_ID).size }
        )
    }
}
