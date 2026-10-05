package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.AttachBegin
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SessionBindOutcome
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncAckResult
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.enroll.SyncUploadRequest
import com.samvaad.android.enroll.SyncUploadResult
import java.io.File
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Session→device attach recovery ([EnrollmentCoordinator.ensureSessionBound])
 * with a scripted fake API and real crypto/vault. Reproduces the exact
 * production failure: an enrolled ACTIVE device whose session lost its
 * binding (expiry + re-login) must rebind without a new device, a recovery
 * code, or a retry loop.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SessionBindTest {

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key
    }

    private class AttachFake : E2eeDeviceApi {
        var begin: (String) -> AttachBegin = { throw AssertionError("begin not stubbed") }
        var complete: (String, String) -> DeviceRecord =
            { _, _ -> throw AssertionError("complete not stubbed") }
        var beginCalls = 0
        var completeCalls = 0
        var lastProof: String? = null

        override suspend fun beginAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): AttachBegin {
            beginCalls++
            return begin(deviceId)
        }

        override suspend fun completeAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            challengeId: String,
            proofBase64: String,
        ): DeviceRecord {
            completeCalls++
            lastProof = proofBase64
            return complete(challengeId, proofBase64)
        }

        override suspend fun enroll(
            session: AuthSession, serverAddress: String, request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enroll in this test")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession, serverAddress: String, deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ): Unit = throw AssertionError("no prekeys in this test")

        override suspend fun listDevices(
            session: AuthSession, serverAddress: String,
        ): DeviceList = throw AssertionError("no list in this test")

        override suspend fun approveDevice(
            session: AuthSession, serverAddress: String, deviceId: String,
        ): DeviceRecord = throw AssertionError("no approval in this test")

        override suspend fun bindDevice(
            session: AuthSession, serverAddress: String, deviceId: String,
            recoveryCode: String,
        ): DeviceRecord = throw AssertionError("no recovery in this test")

        override suspend fun recoverEnroll(
            session: AuthSession, serverAddress: String, recoveryCode: String,
            request: EnrollRequest,
        ): DeviceRecord = throw AssertionError("no recovery in this test")

        override suspend fun listRecipientDevices(
            session: AuthSession, serverAddress: String, username: String,
        ): List<RecipientDeviceRecord> = throw AssertionError("no discovery in this test")

        override suspend fun claimOneTimePrekey(
            session: AuthSession, serverAddress: String, deviceId: String,
            requestId: java.util.UUID,
        ): ClaimedDeviceBundle = throw AssertionError("no discovery in this test")

        override suspend fun submitMessage(
            session: AuthSession, serverAddress: String, requestId: java.util.UUID,
            envelopes: List<MessageEnvelopeSubmit>,
        ): SubmitMessageResult = throw AssertionError("no submission in this test")

        override suspend fun fetchMailbox(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<com.samvaad.android.enroll.MailboxItem> =
            throw AssertionError("no inbox in this test")

        override suspend fun ackMailbox(
            session: AuthSession, serverAddress: String, messageIds: List<java.util.UUID>,
        ): Int = throw AssertionError("no inbox in this test")

        override suspend fun fetchHistory(
            session: AuthSession, serverAddress: String, conversationId: String,
            afterSequence: Long, limit: Int,
        ): List<com.samvaad.android.enroll.HistoryItem> =
            throw AssertionError("no history in this test")

        override suspend fun getSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
        ): SyncCursor = throw AssertionError("no history in this test")

        override suspend fun advanceSyncCursor(
            session: AuthSession, serverAddress: String, conversationId: String,
            throughSequence: Long,
        ): SyncCursor = throw AssertionError("no history in this test")

        override suspend fun listConversations(
            session: AuthSession, serverAddress: String, limit: Int,
        ): List<String> = throw AssertionError("no conversation list in this test")

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

    private lateinit var context: Context
    private lateinit var api: AttachFake
    private lateinit var metadata: FileDeviceMetadataStore
    private lateinit var adapter: AndroidSignalAdapter
    private lateinit var keys: EphemeralKeys

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"
    private val deviceId = "22222222-2222-3333-4444-555555555555"

    private fun coordinator(): EnrollmentCoordinator = EnrollmentCoordinator(
        api = api,
        metadata = metadata,
        adapter = adapter,
        vault = AndroidCryptoVault(context, keys),
    )

    private fun deviceRecord() = DeviceRecord(
        deviceId = deviceId,
        registrationId = 4242,
        signalDeviceId = 2,
        deviceIdentityPublicKey = "aWRlbnRpdHk=",
        signedPrekeyId = 1,
        deviceRole = "COMPANION",
        status = "ACTIVE",
        availablePrekeys = 7,
    )

    /** Adopts a device WITH sealed local identity keys (the post-login state). */
    private fun adoptWithKeys(): AdoptedDevice {
        val identity = adapter.generateIdentity()
        val vault = AndroidCryptoVault(context, keys)
        vault.seal(
            identity.privateHandle,
            CryptoRecordKind.IDENTITY,
            adapter.exportRecord(identity.privateHandle),
        )
        val adopted = AdoptedDevice(
            deviceId = deviceId,
            signalDeviceId = 2,
            registrationId = 4242,
            identityPublicKeyB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
            signedPrekeyId = 1,
            kyberPrekeyId = null,
            otpkHighWaterMark = 0,
            roleHint = "COMPANION",
            statusHint = "ACTIVE",
            identityHandleId = identity.privateHandle.id.toString(),
            signedHandleId = null,
            kyberHandleId = null,
            otpkHandleIds = emptyList(),
            codesAcknowledged = true,
        )
        metadata.writeAdopted(adopted)
        return adopted
    }

    private fun challenge(): AttachBegin.Challenge = AttachBegin.Challenge(
        challengeId = "33333333-2222-3333-4444-555555555555",
        serverEphemeralPublicKey = Base64.getEncoder().encodeToString(ByteArray(32) { 0x07 }),
        expiresAt = null,
    )

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        api = AttachFake()
        metadata = FileDeviceMetadataStore(context)
        adapter = AndroidSignalAdapter()
        keys = EphemeralKeys()
    }

    @Test
    fun alreadyBound_returnsBoundWithoutCrypto(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { AttachBegin.AlreadyBound(deviceRecord()) }

        assertEquals(SessionBindOutcome.Bound, coordinator().ensureSessionBound(session, server))
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun challengeRound_bindsWithWellFormedProof(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { challenge() }
        api.complete = { _, _ -> deviceRecord() }

        assertEquals(SessionBindOutcome.Bound, coordinator().ensureSessionBound(session, server))
        assertEquals(1, api.beginCalls)
        assertEquals(1, api.completeCalls)
        // 32-byte SHA-256 proof, standard Base64.
        val proofBytes = Base64.getDecoder().decode(api.lastProof)
        assertEquals(32, proofBytes.size)
    }

    @Test
    fun noAdoptedDevice_makesNoCalls(): Unit = runBlocking {
        assertEquals(
            SessionBindOutcome.NoAdoptedDevice, coordinator().ensureSessionBound(session, server)
        )
        assertEquals(0, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun revokedTarget_surfacesWithoutComplete(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { throw EnrollException.Forbidden() }

        val outcome = coordinator().ensureSessionBound(session, server)
        assertTrue(outcome is SessionBindOutcome.DeviceUnavailable)
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun boundElsewhere_surfacesWithoutRetry(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { throw EnrollException.Conflict() }

        val outcome = coordinator().ensureSessionBound(session, server)
        assertTrue(outcome is SessionBindOutcome.DeviceUnavailable)
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun staleChallenge_retriesBeginExactlyOnce(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { challenge() }
        var completes = 0
        api.complete = { _, _ ->
            completes++
            if (completes == 1) throw EnrollException.BadRequest()
            deviceRecord()
        }

        assertEquals(SessionBindOutcome.Bound, coordinator().ensureSessionBound(session, server))
        assertEquals(2, api.beginCalls)
        assertEquals(2, api.completeCalls)
    }

    @Test
    fun staleChallengeTwice_surfacesWithoutLooping(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { challenge() }
        api.complete = { _, _ -> throw EnrollException.BadRequest() }

        val outcome = coordinator().ensureSessionBound(session, server)
        assertTrue(outcome is SessionBindOutcome.DeviceUnavailable)
        assertEquals(2, api.beginCalls)
        assertEquals(2, api.completeCalls)
    }

    @Test
    fun transport_isRetryable(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { throw EnrollException.Transport() }

        assertEquals(
            SessionBindOutcome.TransportRetryable,
            coordinator().ensureSessionBound(session, server),
        )
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun expiredSession_needsLogin(): Unit = runBlocking {
        adoptWithKeys()
        api.begin = { throw EnrollException.Unauthorized() }

        assertEquals(
            SessionBindOutcome.NeedsLogin, coordinator().ensureSessionBound(session, server)
        )
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }

    @Test
    fun missingLocalKeys_isCryptoUnavailable(): Unit = runBlocking {
        // Adopted record without handles (bind-style adoption): the proof
        // cannot be computed, so complete must never run.
        metadata.writeAdopted(
            AdoptedDevice(
                deviceId = deviceId,
                signalDeviceId = 2,
                registrationId = 4242,
                identityPublicKeyB64 = "aWRlbnRpdHk=",
                signedPrekeyId = 1,
                kyberPrekeyId = null,
                otpkHighWaterMark = 0,
                roleHint = "COMPANION",
                statusHint = "ACTIVE",
                identityHandleId = null,
                signedHandleId = null,
                kyberHandleId = null,
                otpkHandleIds = emptyList(),
                codesAcknowledged = true,
            )
        )
        api.begin = { challenge() }

        assertEquals(
            SessionBindOutcome.CryptoUnavailable,
            coordinator().ensureSessionBound(session, server),
        )
        assertEquals(1, api.beginCalls)
        assertEquals(0, api.completeCalls)
    }
}
