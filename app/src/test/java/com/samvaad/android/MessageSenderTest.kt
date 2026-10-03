package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.MessageContentSealer
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
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.MessageSender
import com.samvaad.android.session.SendFailure
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import java.io.File
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Outbound message-send tests with a scripted fake API and REAL crypto
 * (adapter + vault sealed under an ephemeral AES key). No network, no UI.
 *
 * The fake submit handler captures every request body: byte-identical
 * bodies across an initial attempt and its live retry prove no
 * re-encryption, and differing bodies across two sends prove ratchet
 * continuity. Directory/claim counters prove zero discovery on the send
 * path.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class MessageSenderTest {

    companion object {
        val PLAINTEXT = "samvaad-slice7-test-message".toByteArray(Charsets.UTF_8)
        const val LOCAL_DEVICE_ID = "11111111-1111-1111-1111-111111111111"
        const val REMOTE_DEVICE_ID = "22222222-2222-3333-4444-555555555555"
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

    private data class SubmitCall(val requestId: UUID, val envelopes: List<MessageEnvelopeSubmit>)

    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: suspend (String, UUID) -> ClaimedDeviceBundle =
            { _, _ -> throw AssertionError("unexpected claim") }
        var submitHandler: suspend (UUID, List<MessageEnvelopeSubmit>) -> SubmitMessageResult =
            { _, _ -> throw AssertionError("unexpected submit") }
        var directoryCalls = 0
        var claimCalls = 0
        val submits = mutableListOf<SubmitCall>()

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
            submits.add(SubmitCall(requestId, envelopes.map { it.copy() }))
            return submitHandler(requestId, envelopes)
        }

        override suspend fun fetchMailbox(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<com.samvaad.android.enroll.MailboxItem> =
            throw AssertionError("no inbox in this slice")

        override suspend fun ackMailbox(
            session: AuthSession,
            serverAddress: String,
            messageIds: List<UUID>,
        ): Int = throw AssertionError("no inbox in this slice")

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
            throw AssertionError("no history in this slice")

        override suspend fun advanceSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncCursor =
            throw AssertionError("no history in this slice")
    }

    private data class RemoteFixture(
        val registrationId: Int = 7001,
        val signalDeviceId: Int = 2,
        val identityB64: String,
        val signedId: Int,
        val signedB64: String,
        val signedSigB64: String,
        val kyberId: Int,
        val kyberB64: String,
        val kyberSigB64: String,
        val otkId: Int,
        val otkB64: String,
    )

    private fun remoteFixture(): RemoteFixture {
        val remote = AndroidSignalAdapter()
        val identity = remote.generateIdentity()
        val signed = remote.generateSignedPrekey(identity, 11)
        val kyber = remote.generateKyberPrekey(identity, 21)
        val otk = remote.generateOneTimePrekey(101)
        return RemoteFixture(
            identityB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
            signedId = signed.prekeyId,
            signedB64 = SpikeCryptoMaterial.encodeBase64(signed.publicKey),
            signedSigB64 = SpikeCryptoMaterial.encodeBase64(signed.signature),
            kyberId = kyber.prekeyId,
            kyberB64 = SpikeCryptoMaterial.encodeBase64(kyber.publicKey),
            kyberSigB64 = SpikeCryptoMaterial.encodeBase64(kyber.signature),
            otkId = otk.prekeyId,
            otkB64 = SpikeCryptoMaterial.encodeBase64(otk.publicKey),
        )
    }

    private lateinit var context: Context
    private lateinit var api: FakeApi
    private lateinit var keys: EphemeralKeys
    private lateinit var adapter: AndroidSignalAdapter
    private lateinit var identityVault: AndroidCryptoVault
    private lateinit var sessionVault: AndroidCryptoVault
    private lateinit var localMeta: FileDeviceMetadataStore
    private lateinit var sessionMeta: FileSessionMetadataStore
    private lateinit var db: MessageDatabase
    private lateinit var sealer: MessageContentSealer

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private fun sender(
        db: MessageDatabase = this.db,
        locks: SessionDeviceLocks = SessionDeviceLocks(),
    ) = MessageSender(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = adapter,
        identityVault = identityVault,
        sessionVault = sessionVault,
        deviceLocks = locks,
        db = db,
        contentSealer = sealer,
    )

    private fun successResult(createdNew: Boolean = true) = SubmitMessageResult(
        messageId = "33333333-3333-3333-3333-333333333333",
        conversationId = "44444444-4444-4444-4444-444444444444",
        sequenceNumber = 7L,
        serverTimestamp = "2026-10-02T10:00:00",
        acceptedRecipientDevices = listOf(REMOTE_DEVICE_ID),
        createdNew = createdNew,
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
        identityVault = AndroidCryptoVault(context, keys)
        sessionVault = AndroidCryptoVault(context, keys, FileSessionMetadataStore.SUBDIR)
        localMeta = FileDeviceMetadataStore(context)
        sessionMeta = FileSessionMetadataStore(context)
        db = androidx.room.Room.inMemoryDatabaseBuilder(context, MessageDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        sealer = MessageContentSealer(keys)
        api.submitHandler = { _, _ -> successResult() }
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun dao() = db.messageDao()

    private fun sealLocalDevice(): AdoptedDevice {
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..3).map { adapter.generateOneTimePrekey(5000 + it) }
        identityVault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        identityVault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        identityVault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            identityVault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
        return AdoptedDevice(
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
        ).also { localMeta.writeAdopted(it) }
    }

    /** Establish a real session for (bob, REMOTE_DEVICE_ID) via the Slice 6 path. */
    private fun establishSession(f: RemoteFixture) {
        api.directoryHandler = {
            listOf(
                RecipientDeviceRecord(
                    deviceId = REMOTE_DEVICE_ID,
                    registrationId = f.registrationId,
                    signalDeviceId = f.signalDeviceId,
                    deviceIdentityPublicKey = f.identityB64,
                    signedPrekeyId = f.signedId,
                    signedPrekey = f.signedB64,
                    signedPrekeySignature = f.signedSigB64,
                    hasAvailableOneTimePrekey = true,
                    deviceRole = "COMPANION",
                    kyberPrekeyId = f.kyberId,
                    kyberPrekey = f.kyberB64,
                    kyberPrekeySignature = f.kyberSigB64,
                )
            )
        }
        api.claimHandler = { id, _ ->
            ClaimedDeviceBundle(
                deviceId = id,
                registrationId = f.registrationId,
                signalDeviceId = f.signalDeviceId,
                deviceIdentityPublicKey = f.identityB64,
                signedPrekeyId = f.signedId,
                signedPrekey = f.signedB64,
                signedPrekeySignature = f.signedSigB64,
                oneTimePrekey = ClaimedOneTimePrekey(f.otkId, f.otkB64),
                deviceRole = "COMPANION",
                kyberPrekeyId = f.kyberId,
                kyberPrekey = f.kyberB64,
                kyberPrekeySignature = f.kyberSigB64,
            )
        }
        val establisher = SessionEstablisher(
            api, localMeta, sessionMeta, adapter, identityVault, sessionVault
        )
        val result = runBlocking { establisher.establish(session, server, "bob", REMOTE_DEVICE_ID) }
        assertTrue(result is com.samvaad.android.session.SessionEstablishResult.Established)
    }

    private fun sessionBlob(): ByteArray = sessionVault.unseal(
        SessionEstablisher.sessionHandleFor(REMOTE_DEVICE_ID), CryptoRecordKind.SESSION
    )

    private fun sessionBlobFile(): File {
        val handle = SessionEstablisher.sessionHandleFor(REMOTE_DEVICE_ID)
        return File(
            File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR),
            "${CryptoRecordKind.SESSION.name}_${handle.id}.svlt",
        )
    }

    // ---- happy paths ----

    @Test
    fun send_happyPath_reusesSessionWithoutDiscovery() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val directoryBefore = api.directoryCalls
        val claimsBefore = api.claimCalls

        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val sent = result as SendResult.Sent
        assertEquals("PREKEY_INIT", sent.envelopeType)
        assertTrue(sent.createdNew)
        assertEquals("33333333-3333-3333-3333-333333333333", sent.messageId)
        assertEquals(REMOTE_DEVICE_ID, sent.entry.remoteDeviceId)
        // Zero discovery on the send path.
        assertEquals(directoryBefore, api.directoryCalls)
        assertEquals(claimsBefore, api.claimCalls)
        assertEquals(1, api.submits.size)

        // Envelope identity comes from durable metadata, not parameters.
        val env = api.submits.single().envelopes.single()
        assertEquals(LOCAL_DEVICE_ID, env.senderDeviceId)
        assertEquals(REMOTE_DEVICE_ID, env.recipientDeviceId)
        assertEquals("PREKEY_INIT", env.envelopeType)
        assertTrue(java.util.Base64.getDecoder().decode(env.ciphertextBase64).isNotEmpty())
    }

    @Test
    fun secondSend_advancesRatchet_staysPrekeyInit() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val s = sender()
        val first = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val second = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue(first is SendResult.Sent && second is SendResult.Sent)
        val c1 = api.submits[0].envelopes.single().ciphertextBase64
        val c2 = api.submits[1].envelopes.single().ciphertextBase64
        assertFalse(c1 == c2)
        assertEquals("PREKEY_INIT", api.submits[1].envelopes.single().envelopeType)
        // Request IDs are per logical message, never reused across sends.
        assertFalse(api.submits[0].requestId == api.submits[1].requestId)
        // The sealed session advanced and stays usable.
        adapter.inspectSession(sessionBlob())
    }

    @Test
    fun persistenceHappensBeforeSubmit() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val preBlob = sessionBlob()
        var observedDuringSubmit: ByteArray? = null
        api.submitHandler = { _, _ ->
            observedDuringSubmit = sessionBlob()
            successResult()
        }
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue(result is SendResult.Sent)
        // By the time HTTP runs, disk already holds the advanced state.
        assertNotNull(observedDuringSubmit)
        assertFalse(preBlob.contentEquals(observedDuringSubmit))
        adapter.inspectSession(observedDuringSubmit!!)
    }

    // ---- failure invariants ----

    @Test
    fun sealFailure_preventsHttp() {
        sealLocalDevice()
        establishSession(remoteFixture())
        // Plant a directory at the blob path: seal fails with storage failure.
        val blobFile = sessionBlobFile()
        assertTrue(blobFile.delete())
        assertTrue(blobFile.mkdirs())
        try {
            val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
            val failed = result as SendResult.Failed
            assertTrue(failed.kind is SendFailure.SessionUnavailable)
            assertNull(failed.retry)
            assertTrue(api.submits.isEmpty())
        } finally {
            blobFile.delete()
        }
    }

    @Test
    fun transportFailure_retryResubmitsIdenticalBytes() {
        sealLocalDevice()
        establishSession(remoteFixture())
        var failFirst = true
        api.submitHandler = { _, _ ->
            if (failFirst) {
                failFirst = false
                throw EnrollException.Transport()
            }
            successResult(createdNew = false)
        }
        val first = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val failed = first as SendResult.Failed
        assertEquals(SendFailure.TransportRetryable, failed.kind)
        assertNotNull(failed.retry)
        // Live retry: same requestId, same envelope bytes — no re-encryption.
        val retried = runBlocking { failed.retry!!.invoke() }
        val sent = retried as SendResult.Sent
        assertFalse(sent.createdNew)
        assertEquals(2, api.submits.size)
        assertEquals(api.submits[0].requestId, api.submits[1].requestId)
        assertEquals(
            api.submits[0].envelopes.single().ciphertextBase64,
            api.submits[1].envelopes.single().ciphertextBase64,
        )
    }

    @Test
    fun conflict_failsClosedWithoutRetry() {
        sealLocalDevice()
        establishSession(remoteFixture())
        api.submitHandler = { _, _ -> throw EnrollException.Conflict() }
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val failed = result as SendResult.Failed
        assertEquals(SendFailure.Conflict, failed.kind)
        assertNull(failed.retry)
        assertEquals(1, api.submits.size)
    }

    @Test
    fun authAndValidationFailures_mapWithoutRetry() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val s = sender()
        api.submitHandler = { _, _ -> throw EnrollException.Unauthorized() }
        var r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Failed
        assertEquals(SendFailure.Unauthorized, r.kind)
        assertNull(r.retry)
        api.submitHandler = { _, _ -> throw EnrollException.Forbidden() }
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Failed
        assertEquals(SendFailure.Forbidden, r.kind)
        api.submitHandler = { _, _ -> throw EnrollException.NotFound() }
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Failed
        assertEquals(SendFailure.NotFound, r.kind)
        api.submitHandler = { _, _ -> throw EnrollException.BadRequest() }
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Failed
        assertEquals(SendFailure.BadRequest, r.kind)
        api.submitHandler = { _, _ -> throw EnrollException.Malformed() }
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Failed
        assertTrue(r.kind is SendFailure.Rejected)
        assertNull(r.retry)
    }

    @Test
    fun missingSessionStates_failClosedWithoutHttp() {
        sealLocalDevice()
        val s = sender()
        // No entry at all.
        var r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue((r as SendResult.Failed).kind is SendFailure.SessionUnavailable)

        establishSession(remoteFixture())
        // Wrong username for the entry: miss, never migrate.
        r = runBlocking { s.send(session, server, "carol", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue((r as SendResult.Failed).kind is SendFailure.SessionUnavailable)

        // Pinned identity tampered out of band.
        val entry = sessionMeta.read(REMOTE_DEVICE_ID)!!
        sessionMeta.write(entry.copy(remoteIdentityPublicKeyB64 = remoteFixture().identityB64))
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertEquals(SendFailure.IdentityMismatch, (r as SendResult.Failed).kind)
        assertTrue(api.submits.isEmpty())
    }

    @Test
    fun corruptBlob_failsClosedWithoutHttp() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val inverted = sessionBlob().copyOf().also { out ->
            for (i in out.indices) out[i] = out[i].toInt().inv().toByte()
        }
        sessionBlobFile().writeBytes(
            // Re-seal is impossible without the key state; overwrite the
            // envelope file directly to simulate on-disk corruption.
            inverted
        )
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        // GCM authentication rejects the tampered envelope first.
        assertTrue((result as SendResult.Failed).kind is SendFailure.SessionUnavailable)
        assertTrue(api.submits.isEmpty())
    }

    @Test
    fun noAdoptedDevice_isCryptoUnavailable() {
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertEquals(SendFailure.CryptoUnavailable, (result as SendResult.Failed).kind)
        assertTrue(api.submits.isEmpty())
    }

    @Test
    fun invalidTargets_rejectedWithoutNetwork() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val s = sender()
        var r = runBlocking { s.send(session, server, "", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue((r as SendResult.Failed).kind is SendFailure.Rejected)
        r = runBlocking { s.send(session, server, "bob", REMOTE_DEVICE_ID, ByteArray(0)) }
        assertTrue((r as SendResult.Failed).kind is SendFailure.Rejected)
        assertEquals(0, api.submits.size)
    }

    @Test
    fun concurrentSameDeviceSends_areSerialized() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val inFlight = AtomicInteger(0)
        val maxInFlight = AtomicInteger(0)
        api.submitHandler = { _, _ ->
            val now = inFlight.incrementAndGet()
            maxInFlight.accumulateAndGet(now, Math::max)
            delay(150)
            inFlight.decrementAndGet()
            successResult()
        }
        val s = sender()
        runBlocking {
            val a = async { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
            val b = async { s.send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
            assertTrue(a.await() is SendResult.Sent)
            assertTrue(b.await() is SendResult.Sent)
        }
        // Fully sequential: HTTP never overlapped, ciphertexts differ
        // (each encrypted from the previously persisted state).
        assertEquals(1, maxInFlight.get())
        assertEquals(2, api.submits.size)
        assertFalse(
            api.submits[0].envelopes.single().ciphertextBase64 ==
                api.submits[1].envelopes.single().ciphertextBase64
        )
        adapter.inspectSession(sessionBlob())
    }

    @Test
    fun establishedViaFallback_sendsPrekeyInit() {
        sealLocalDevice()
        val f = remoteFixture()
        api.directoryHandler = {
            listOf(
                RecipientDeviceRecord(
                    deviceId = REMOTE_DEVICE_ID,
                    registrationId = f.registrationId,
                    signalDeviceId = f.signalDeviceId,
                    deviceIdentityPublicKey = f.identityB64,
                    signedPrekeyId = f.signedId,
                    signedPrekey = f.signedB64,
                    signedPrekeySignature = f.signedSigB64,
                    hasAvailableOneTimePrekey = false,
                    deviceRole = "COMPANION",
                    kyberPrekeyId = f.kyberId,
                    kyberPrekey = f.kyberB64,
                    kyberPrekeySignature = f.kyberSigB64,
                )
            )
        }
        api.claimHandler = { id, _ ->
            ClaimedDeviceBundle(
                deviceId = id,
                registrationId = f.registrationId,
                signalDeviceId = f.signalDeviceId,
                deviceIdentityPublicKey = f.identityB64,
                signedPrekeyId = f.signedId,
                signedPrekey = f.signedB64,
                signedPrekeySignature = f.signedSigB64,
                oneTimePrekey = null,
                deviceRole = "COMPANION",
                kyberPrekeyId = f.kyberId,
                kyberPrekey = f.kyberB64,
                kyberPrekeySignature = f.kyberSigB64,
            )
        }
        val establisher = SessionEstablisher(
            api, localMeta, sessionMeta, adapter, identityVault, sessionVault
        )
        val established = runBlocking { establisher.establish(session, server, "bob", REMOTE_DEVICE_ID) }
        assertTrue(established is com.samvaad.android.session.SessionEstablishResult.Established)
        assertEquals(
            EstablishedVia.SIGNED_FALLBACK,
            (established as com.samvaad.android.session.SessionEstablishResult.Established).entry.establishedVia,
        )
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val sent = result as SendResult.Sent
        assertEquals("PREKEY_INIT", sent.envelopeType)
    }

    // ---- Slice 9 Step 3: durable outbound state machine ----

    private fun fileSender(
        fileDb: MessageDatabase,
        fileAdapter: AndroidSignalAdapter = AndroidSignalAdapter(),
        locks: SessionDeviceLocks = SessionDeviceLocks(),
    ) = MessageSender(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = fileAdapter,
        identityVault = identityVault,
        sessionVault = sessionVault,
        deviceLocks = locks,
        db = fileDb,
        contentSealer = MessageContentSealer(keys),
    )

    private fun containsWindow(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    @Test
    fun sendHappy_rowTransitionsToSentWithServerIdentity() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val sent = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Sent
        val row = runBlocking { dao().byMessageId(sent.localMessageId) }!!
        assertEquals(com.samvaad.android.db.SendState.SENT, row.sendState)
        // Server-assigned identity reconciled onto the local row.
        assertEquals("33333333-3333-3333-3333-333333333333", row.serverMessageId)
        assertEquals(sent.messageId, row.serverMessageId)
        assertEquals("44444444-4444-4444-4444-444444444444", row.conversationId)
        assertEquals(7L, row.sequenceNumber)
        assertEquals("2026-10-02T10:00:00", row.serverTimestamp)
        assertEquals(sent.localMessageId, row.messageId)
    }

    @Test
    fun sendHappy_storedBytesEqualSubmittedBytes_rowHasNoPlaintext() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val sent = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Sent
        val submitted = api.submits.single()
        val row = runBlocking { dao().byMessageId(sent.localMessageId) }!!
        // Exact stored requestId/ciphertext equal the submitted ones.
        assertEquals(submitted.requestId.toString(), row.requestId)
        assertArrayEquals(
            java.util.Base64.getDecoder().decode(submitted.envelopes.single().ciphertextBase64),
            row.ciphertext,
        )
        // Sealed plaintext opens; no cleartext anywhere in the row.
        assertArrayEquals(PLAINTEXT, sealer.open(row.messageId, row.plaintextSealed!!))
        assertFalse(containsWindow(row.plaintextSealed, PLAINTEXT))
        assertEquals(com.samvaad.android.db.MessageDirection.OUT, row.direction)
        assertEquals(LOCAL_DEVICE_ID, row.senderDeviceId)
        assertEquals(REMOTE_DEVICE_ID, row.recipientDeviceId)
    }

    @Test
    fun transportFailureAfterSeal_preservesRow_recoverResubmitsIdentically() {
        sealLocalDevice()
        establishSession(remoteFixture())
        var failFirst = true
        api.submitHandler = { _, _ ->
            if (failFirst) {
                failFirst = false
                throw EnrollException.Transport()
            }
            successResult(createdNew = false)
        }
        val first = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertTrue((first as SendResult.Failed).kind is SendFailure.TransportRetryable)
        // Row stays SEALED with original bytes: nothing mutated, nothing lost.
        val localId = api.submits.single().let {
            runBlocking { dao().byRequestId(it.requestId.toString()) }!!.messageId
        }
        val sealed = runBlocking { dao().byMessageId(localId) }!!
        assertEquals(com.samvaad.android.db.SendState.SEALED, sealed.sendState)
        // Recovery resubmits the identical request without re-encryption.
        val outcomes = runBlocking { sender().recoverUnsent(session, server, "bob", REMOTE_DEVICE_ID) }
        val resubmitted = outcomes.single() as com.samvaad.android.session.RecoverOutcome.Resubmitted
        assertEquals(localId, resubmitted.messageId)
        assertFalse(resubmitted.sent.createdNew)
        assertEquals(2, api.submits.size)
        assertEquals(api.submits[0].requestId, api.submits[1].requestId)
        assertEquals(
            api.submits[0].envelopes.single().ciphertextBase64,
            api.submits[1].envelopes.single().ciphertextBase64,
        )
        assertEquals(
            com.samvaad.android.db.SendState.SENT,
            runBlocking { dao().byMessageId(localId) }!!.sendState,
        )
    }

    @Test
    fun replayResponse_marksSent() {
        sealLocalDevice()
        establishSession(remoteFixture())
        api.submitHandler = { _, _ -> successResult(createdNew = false) }
        val sent = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) } as SendResult.Sent
        assertFalse(sent.createdNew)
        assertEquals(
            com.samvaad.android.db.SendState.SENT,
            runBlocking { dao().byMessageId(sent.localMessageId) }!!.sendState,
        )
    }

    @Test
    fun conflict_preservesRow_usesFreshIdsNextTime() {
        sealLocalDevice()
        establishSession(remoteFixture())
        api.submitHandler = { _, _ -> throw EnrollException.Conflict() }
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val failed = result as SendResult.Failed
        assertEquals(SendFailure.Conflict, failed.kind)
        assertNull(failed.retry)
        // 409 is terminal for these bytes: row stays SEALED, bytes kept.
        val row = runBlocking { dao().byRequestId(api.submits.single().requestId.toString()) }!!
        assertEquals(com.samvaad.android.db.SendState.SEALED, row.sendState)
        val burnedCiphertext = row.ciphertext!!.copyOf()
        // A new logical message mints fresh IDs and re-encrypts (ratchet
        // advanced again) — never silently retries the burned request.
        api.submitHandler = { _, _ -> successResult() }
        runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertEquals(2, api.submits.size)
        assertFalse(api.submits[0].requestId == api.submits[1].requestId)
        assertFalse(
            api.submits[0].envelopes.single().ciphertextBase64 ==
                api.submits[1].envelopes.single().ciphertextBase64
        )
        assertArrayEquals(burnedCiphertext, runBlocking { dao().byMessageId(row.messageId) }!!.ciphertext)
    }

    @Test
    fun badRequest_preservesRow_noReencrypt() {
        sealLocalDevice()
        establishSession(remoteFixture())
        api.submitHandler = { _, _ -> throw EnrollException.BadRequest() }
        val result = runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        assertEquals(SendFailure.BadRequest, (result as SendResult.Failed).kind)
        val row = runBlocking { dao().byRequestId(api.submits.single().requestId.toString()) }!!
        assertEquals(com.samvaad.android.db.SendState.SEALED, row.sendState)
    }

    @Test
    fun pendingSeal_recovery_supersedesWithFreshAttempt() {
        sealLocalDevice()
        establishSession(remoteFixture())
        // Simulate the crash window: a row whose session was never
        // committed (old IDs/ciphertext must never be submitted).
        val staleId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        val staleRequest = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        val staleCipher = ByteArray(48) { 0x2A }
        runBlocking {
            dao().insertIgnore(
                com.samvaad.android.db.MessageEntity(
                    messageId = staleId,
                    conversationId = "",
                    sequenceNumber = 0L,
                    direction = com.samvaad.android.db.MessageDirection.OUT,
                    senderDeviceId = LOCAL_DEVICE_ID,
                    recipientDeviceId = REMOTE_DEVICE_ID,
                    envelopeType = "PREKEY_INIT",
                    ciphertext = staleCipher,
                    plaintextSealed = sealer.seal(staleId, PLAINTEXT),
                    sendState = com.samvaad.android.db.SendState.PENDING_SEAL,
                    acked = false,
                    requestId = staleRequest,
                    serverMessageId = null,
                    serverTimestamp = "",
                    createdAt = 1L,
                )
            )
        }
        api.submitHandler = { _, _ -> successResult() }
        val outcomes = runBlocking { sender().recoverUnsent(session, server, "bob", REMOTE_DEVICE_ID) }
        val superseded = outcomes.single() as com.samvaad.android.session.RecoverOutcome.Superseded
        assertEquals(staleId, superseded.oldMessageId)
        // Old row discarded, never submitted…
        assertNull(runBlocking { dao().byMessageId(staleId) })
        assertTrue(api.submits.none { it.requestId.toString() == staleRequest })
        assertTrue(api.submits.none {
            it.envelopes.single().ciphertextBase64 ==
                java.util.Base64.getEncoder().encodeToString(staleCipher)
        })
        // …fresh attempt sent with new IDs through the normal path.
        val fresh = superseded.fresh as SendResult.Sent
        assertFalse(fresh.localMessageId == staleId)
        assertArrayEquals(PLAINTEXT, sealer.open(
            fresh.localMessageId,
            runBlocking { dao().byMessageId(fresh.localMessageId) }!!.plaintextSealed!!,
        ))
    }

    @Test
    fun sentRows_ignoredByRecovery_noDuplicateSubmit() {
        sealLocalDevice()
        establishSession(remoteFixture())
        runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        val callsBefore = api.submits.size
        val outcomes = runBlocking { sender().recoverUnsent(session, server, "bob", REMOTE_DEVICE_ID) }
        assertTrue(outcomes.isEmpty())
        assertEquals(callsBefore, api.submits.size)
    }

    @Test
    fun noPlaintextInDatabaseFiles() {
        sealLocalDevice()
        establishSession(remoteFixture())
        runBlocking { sender().send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT) }
        db.close()
        // Reopen to force WAL checkpoint, then scan every message-state
        // file: sealed or opaque bytes only, never cleartext.
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
                    containsWindow(file.readBytes(), PLAINTEXT),
                )
            }
        }
    }

    @Test
    fun restartSealedRow_resubmitsIdentically() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val fileDb = MessageDatabase.open(context)
        try {
            var failFirst = true
            api.submitHandler = { _, _ ->
                if (failFirst) {
                    failFirst = false
                    throw EnrollException.Transport()
                }
                successResult(createdNew = false)
            }
            val first = runBlocking {
                fileSender(fileDb).send(session, server, "bob", REMOTE_DEVICE_ID, PLAINTEXT)
            }
            assertTrue((first as SendResult.Failed).kind is SendFailure.TransportRetryable)
            val original = api.submits.single()
            fileDb.close()
            // Simulated restart: new adapter, new sender, same vaults/keys/files.
            val freshAdapter = AndroidSignalAdapter()
            val reopened = MessageDatabase.open(context)
            try {
                val recovered = MessageSender(
                    api = api,
                    localMetadata = localMeta,
                    sessions = sessionMeta,
                    adapter = freshAdapter,
                    identityVault = identityVault,
                    sessionVault = sessionVault,
                    deviceLocks = SessionDeviceLocks(),
                    db = reopened,
                    contentSealer = MessageContentSealer(keys),
                )
                val outcomes = runBlocking {
                    recovered.recoverUnsent(session, server, "bob", REMOTE_DEVICE_ID)
                }
                val resubmitted = outcomes.single() as com.samvaad.android.session.RecoverOutcome.Resubmitted
                assertFalse(resubmitted.sent.createdNew)
                assertEquals(2, api.submits.size)
                assertEquals(original.requestId, api.submits[1].requestId)
                assertEquals(
                    original.envelopes.single().ciphertextBase64,
                    api.submits[1].envelopes.single().ciphertextBase64,
                )
            } finally {
                reopened.close()
            }
        } finally {
            if (fileDb.isOpen) fileDb.close()
        }
    }

    @Test
    fun restartPendingSeal_supersedesFresh() {
        sealLocalDevice()
        establishSession(remoteFixture())
        val fileDb = MessageDatabase.open(context)
        try {
            val staleId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            runBlocking {
                fileDb.messageDao().insertIgnore(
                    com.samvaad.android.db.MessageEntity(
                        messageId = staleId,
                        conversationId = "",
                        sequenceNumber = 0L,
                        direction = com.samvaad.android.db.MessageDirection.OUT,
                        senderDeviceId = LOCAL_DEVICE_ID,
                        recipientDeviceId = REMOTE_DEVICE_ID,
                        envelopeType = "PREKEY_INIT",
                        ciphertext = ByteArray(32) { 0x2A },
                        plaintextSealed = MessageContentSealer(keys).seal(staleId, PLAINTEXT),
                        sendState = com.samvaad.android.db.SendState.PENDING_SEAL,
                        acked = false,
                        requestId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                        serverMessageId = null,
                        serverTimestamp = "",
                        createdAt = 1L,
                    )
                )
            }
            fileDb.close()
            api.submitHandler = { _, _ -> successResult() }
            val reopened = MessageDatabase.open(context)
            try {
                val recovered = fileSender(reopened)
                val outcomes = runBlocking {
                    recovered.recoverUnsent(session, server, "bob", REMOTE_DEVICE_ID)
                }
                val superseded = outcomes.single() as com.samvaad.android.session.RecoverOutcome.Superseded
                assertEquals(staleId, superseded.oldMessageId)
                assertTrue(superseded.fresh is SendResult.Sent)
                assertNull(runBlocking { reopened.messageDao().byMessageId(staleId) })
            } finally {
                reopened.close()
            }
        } finally {
            if (fileDb.isOpen) fileDb.close()
        }
    }
}
