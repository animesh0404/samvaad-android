package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.ApprovalLoad
import com.samvaad.android.enroll.ApproveOutcome
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FailKind
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecoveryMode
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 10 state-machine tests with a scripted fake API and real
 * crypto/vault (ephemeral AES key standing in for the Keystore key).
 * Covers: PENDING check-status convergence (still-pending / approved /
 * revoked / absent), Denied + fresh enrollment, bind recovery, new-device
 * recovery, single-use-code discipline, and the run guard. Recovery codes
 * here are fake sentinel strings, never persisted.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice10CoordinatorTest {

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key
    }

    private class FakeApi10 : E2eeDeviceApi {
        var enrollHandler: (EnrollRequest) -> EnrollResult =
            { throw AssertionError("unexpected enroll") }
        var uploadHandler: (String, List<OneTimePrekeyUpload>) -> Unit = { _, _ -> }
        var listHandler: () -> DeviceList =
            { DeviceList("ENROLLED_ACTIVE", emptyList()) }
        var approveHandler: (String) -> DeviceRecord =
            { throw AssertionError("unexpected approve") }
        var bindHandler: (String, String) -> DeviceRecord =
            { _, _ -> throw AssertionError("unexpected bind") }
        var recoverHandler: (String, EnrollRequest) -> DeviceRecord =
            { _, _ -> throw AssertionError("unexpected recoverEnroll") }
        var enrollCalls = 0
        var approveCalls = 0
        var bindCalls = 0
        var recoverCalls = 0
        var listCalls = 0
        val posted = mutableListOf<EnrollRequest>()
        val seenCodes = mutableListOf<String>()
        val uploads = mutableListOf<Pair<String, List<OneTimePrekeyUpload>>>()

        override suspend fun enroll(
            session: AuthSession,
            serverAddress: String,
            request: EnrollRequest,
        ): EnrollResult {
            enrollCalls++
            posted.add(request)
            return enrollHandler(request)
        }

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) {
            uploads.add(deviceId to batch)
            uploadHandler(deviceId, batch)
        }

        override suspend fun listDevices(
            session: AuthSession,
            serverAddress: String,
        ): DeviceList {
            listCalls++
            return listHandler()
        }

        override suspend fun approveDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): DeviceRecord {
            approveCalls++
            return approveHandler(deviceId)
        }

        override suspend fun bindDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            recoveryCode: String,
        ): DeviceRecord {
            bindCalls++
            seenCodes.add(recoveryCode)
            return bindHandler(deviceId, recoveryCode)
        }

        override suspend fun recoverEnroll(
            session: AuthSession,
            serverAddress: String,
            recoveryCode: String,
            request: EnrollRequest,
        ): DeviceRecord {
            recoverCalls++
            seenCodes.add(recoveryCode)
            posted.add(request)
            return recoverHandler(recoveryCode, request)
        }

        override suspend fun listRecipientDevices(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): List<com.samvaad.android.enroll.RecipientDeviceRecord> =
            throw AssertionError("no discovery in this slice")

        override suspend fun claimOneTimePrekey(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            requestId: java.util.UUID,
        ): com.samvaad.android.enroll.ClaimedDeviceBundle =
            throw AssertionError("no discovery in this slice")

        override suspend fun submitMessage(
            session: AuthSession,
            serverAddress: String,
            requestId: java.util.UUID,
            envelopes: List<com.samvaad.android.enroll.MessageEnvelopeSubmit>,
        ): com.samvaad.android.enroll.SubmitMessageResult =
            throw AssertionError("no submission in this slice")

        override suspend fun fetchMailbox(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<com.samvaad.android.enroll.MailboxItem> =
            throw AssertionError("no inbox in this slice")

        override suspend fun ackMailbox(
            session: AuthSession,
            serverAddress: String,
            messageIds: List<java.util.UUID>,
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

    private lateinit var context: Context
    private lateinit var api: FakeApi10
    private lateinit var metadata: FileDeviceMetadataStore
    private lateinit var keys: EphemeralKeys

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private fun coordinator(): EnrollmentCoordinator = EnrollmentCoordinator(
        api = api,
        metadata = metadata,
        adapter = AndroidSignalAdapter(),
        vault = AndroidCryptoVault(context, keys),
    )

    private fun pendingRow(
        identityB64: String,
        status: String = "PENDING",
        registrationId: Int = 4242,
    ) = DeviceRecord(
        deviceId = "aaaaaaaa-2222-3333-4444-555555555555",
        registrationId = registrationId,
        signalDeviceId = 2,
        deviceIdentityPublicKey = identityB64,
        signedPrekeyId = 1,
        deviceRole = "COMPANION",
        status = status,
        availablePrekeys = 0,
    )

    /** Seed a PENDING adopted device through the real bootstrap path. */
    private fun seedPending(): DeviceRecord {
        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listed) }
        api.enrollHandler = { req ->
            val row = pendingRow(req.deviceIdentityPublicKey, "PENDING", req.registrationId)
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.PendingApproval)
        return metadata.readAdopted().let {
            requireNotNull(it)
            pendingRow(it.identityPublicKeyB64)
        }
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        api = FakeApi10()
        metadata = FileDeviceMetadataStore(context)
        keys = EphemeralKeys()
    }

    @Test
    fun pending_checkStatus_stillPending_preservesAdoption() {
        seedPending()
        val adoptedId = metadata.readAdopted()!!.deviceId
        val uploadsBefore = api.uploads.size

        val final = runBlocking { coordinator().runBootstrap(session, server) }

        assertTrue(final is BootstrapFinal.PendingApproval)
        assertEquals(adoptedId, metadata.readAdopted()!!.deviceId)
        // Still pending: no OTPK upload is ever attempted.
        assertEquals(uploadsBefore, api.uploads.size)
    }

    @Test
    fun pending_approved_uploadsRetainedBatch_goesActive() {
        seedPending()
        val identity = metadata.readAdopted()!!.identityPublicKeyB64
        val activeRow = pendingRow(identity, "ACTIVE")
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(activeRow)) }

        val final = runBlocking { coordinator().runBootstrap(session, server) }

        val active = final as BootstrapFinal.Active
        assertTrue(active.deviceLabel.contains("#2"))
        assertEquals(1, api.uploads.size)
        assertEquals(activeRow.deviceId, api.uploads.single().first)
        assertEquals(100, api.uploads.single().second.size)
        assertEquals("ACTIVE", metadata.readAdopted()!!.statusHint)
        assertEquals("COMPANION", metadata.readAdopted()!!.roleHint)
        assertEquals(2, metadata.readAdopted()!!.signalDeviceId)
    }

    @Test
    fun pending_revoked_convergesDenied_notReconciliation() {
        seedPending()
        val identity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList(
                "RECOVERY_REQUIRED",
                listOf(pendingRow(identity, "REVOKED"))
            )
        }

        val final = runBlocking { coordinator().runBootstrap(session, server) }

        assertTrue(final is BootstrapFinal.Denied)
        // The dead row is still recorded (for the label), never resurrected.
        assertEquals(
            "aaaaaaaa-2222-3333-4444-555555555555",
            metadata.readAdopted()!!.deviceId,
        )
    }

    @Test
    fun pending_absent_convergesDenied() {
        seedPending()
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", emptyList()) }

        val final = runBlocking { coordinator().runBootstrap(session, server) }

        assertTrue(final is BootstrapFinal.Denied)
    }

    @Test
    fun denied_clearAndFresh_enrollsNewRow_neverReusesDeadId() {
        seedPending()
        val deadId = metadata.readAdopted()!!.deviceId
        val deadIdentity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", emptyList()) }
        assertTrue(
            runBlocking { coordinator().runBootstrap(session, server) }
                is BootstrapFinal.Denied
        )

        coordinator().clearDeniedState()
        assertNull(metadata.readAdopted())

        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listed) }
        api.enrollHandler = { req ->
            val row = DeviceRecord(
                deviceId = "bbbbbbbb-2222-3333-4444-555555555555",
                registrationId = req.registrationId,
                signalDeviceId = 3,
                deviceIdentityPublicKey = req.deviceIdentityPublicKey,
                signedPrekeyId = req.signedPrekeyId,
                deviceRole = "COMPANION",
                status = "ACTIVE",
                availablePrekeys = 0,
            )
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }

        assertTrue(final is BootstrapFinal.Active)
        val adopted = metadata.readAdopted()!!
        assertEquals("bbbbbbbb-2222-3333-4444-555555555555", adopted.deviceId)
        // Fresh lineage: new identity, dead row never resurrected.
        assertFalse(adopted.identityPublicKeyB64 == deadIdentity)
        assertEquals(2, api.enrollCalls)
    }

    @Test
    fun bind_success_adoptsWithoutKeys_goesActive() {
        val target = DeviceRecord(
            deviceId = "cccccccc-2222-3333-4444-555555555555",
            registrationId = 5150,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VydmVyLWtleQ==",
            signedPrekeyId = 9,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 42,
            kyberPrekeyId = 11,
        )
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(target)) }
        api.bindHandler = { _, _ -> target }

        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-BIND-1", RecoveryMode.Bind(target.deviceId))
        }

        assertTrue(final is BootstrapFinal.Active)
        assertEquals(1, api.bindCalls)
        // Bind creates no key material and uploads nothing.
        assertTrue(api.uploads.isEmpty())
        val adopted = metadata.readAdopted()!!
        assertEquals(target.deviceId, adopted.deviceId)
        assertEquals("PRIMARY", adopted.roleHint)
        assertEquals(1, adopted.signalDeviceId)
        assertFalse(adopted.hasLocalKeys)
        assertNull(adopted.identityHandleId)
        assertTrue(adopted.codesAcknowledged)
        // The sentinel code reached the fake wire only, never the metadata file.
        val stored = FileDeviceMetadataStore.rawFile(context).readBytes()
        assertFalse(String(stored, Charsets.UTF_8).contains("SENTINEL-BIND-1"))
    }

    @Test
    fun bind_conflict_convergesThroughList_whenTargetActive() {
        val target = DeviceRecord(
            deviceId = "cccccccc-2222-3333-4444-555555555555",
            registrationId = 5150,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VydmVyLWtleQ==",
            signedPrekeyId = 9,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 42,
        )
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(target)) }
        api.bindHandler = { _, _ -> throw EnrollException.Conflict() }

        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-BIND-2", RecoveryMode.Bind(target.deviceId))
        }

        // Session-already-bound inference: this session only ever attempted
        // this target, and the target reads ACTIVE.
        assertTrue(final is BootstrapFinal.Active)
        assertEquals(target.deviceId, metadata.readAdopted()!!.deviceId)
    }

    @Test
    fun bind_conflict_revokedTarget_failsSafe() {
        val target = DeviceRecord(
            deviceId = "cccccccc-2222-3333-4444-555555555555",
            registrationId = 5150,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VydmVyLWtleQ==",
            signedPrekeyId = 9,
            deviceRole = "PRIMARY",
            status = "REVOKED",
            availablePrekeys = 0,
        )
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", listOf(target)) }
        api.bindHandler = { _, _ -> throw EnrollException.Conflict() }

        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-BIND-3", RecoveryMode.Bind(target.deviceId))
        }

        assertEquals(BootstrapFinal.Failed(FailKind.REJECTED), final)
        assertNull(metadata.readAdopted())
    }

    @Test
    fun recoverNewDevice_success_uploadsBatch_goesActiveAcked() {
        api.recoverHandler = { _, req ->
            DeviceRecord(
                deviceId = "dddddddd-2222-3333-4444-555555555555",
                registrationId = req.registrationId,
                signalDeviceId = 2,
                deviceIdentityPublicKey = req.deviceIdentityPublicKey,
                signedPrekeyId = req.signedPrekeyId,
                deviceRole = "COMPANION",
                status = "ACTIVE",
                availablePrekeys = 0,
                kyberPrekeyId = req.kyberPrekeyId,
            )
        }

        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-NEW-1", RecoveryMode.NewDevice)
        }

        val active = final as BootstrapFinal.Active
        assertTrue(active.codesAcknowledged)
        assertEquals(1, api.recoverCalls)
        assertEquals(1, api.uploads.size)
        assertEquals(100, api.uploads.single().second.size)
        // Role/signal come from the server row, identity echoes our material.
        val adopted = metadata.readAdopted()!!
        assertEquals("dddddddd-2222-3333-4444-555555555555", adopted.deviceId)
        assertEquals("COMPANION", adopted.roleHint)
        assertEquals(2, adopted.signalDeviceId)
        assertEquals(api.posted.single().deviceIdentityPublicKey, adopted.identityPublicKeyB64)
        assertTrue(adopted.hasLocalKeys)
    }

    @Test
    fun recoverNewDevice_transportLoss_reconcilesWithoutBlindRetry() {
        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", listed) }
        var first = true
        api.recoverHandler = { _, req ->
            if (first) {
                first = false
                throw IOException("connection lost")
            }
            throw EnrollException.Conflict()
        }

        val lost = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-NEW-2", RecoveryMode.NewDevice)
        }
        // Uncertain outcome: exactly one POST, nothing adopted, retryable.
        assertEquals(BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE), lost)
        assertEquals(1, api.recoverCalls)
        assertNull(metadata.readAdopted())
        assertTrue(api.uploads.isEmpty())

        // The lost response had actually created the row: the next attempt
        // (a NEW code) hits 409, reconciles by identity, and provisions.
        val identity = api.posted.single().deviceIdentityPublicKey
        listed = listOf(
            DeviceRecord(
                deviceId = "dddddddd-2222-3333-4444-555555555555",
                registrationId = api.posted.single().registrationId,
                signalDeviceId = 2,
                deviceIdentityPublicKey = identity,
                signedPrekeyId = api.posted.single().signedPrekeyId,
                deviceRole = "COMPANION",
                status = "ACTIVE",
                availablePrekeys = 0,
            )
        )
        val converged = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-NEW-3", RecoveryMode.NewDevice)
        }
        assertTrue(converged is BootstrapFinal.Active)
        assertEquals(1, api.uploads.size)
        assertEquals(
            "dddddddd-2222-3333-4444-555555555555",
            metadata.readAdopted()!!.deviceId,
        )
    }

    @Test
    fun recoverNewDevice_conflict_noActiveMatch_failsSafe() {
        api.recoverHandler = { _, _ -> throw EnrollException.Conflict() }
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", emptyList()) }

        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "SENTINEL-NEW-4", RecoveryMode.NewDevice)
        }

        assertEquals(BootstrapFinal.Failed(FailKind.REJECTED), final)
        assertNull(metadata.readAdopted())
        assertTrue(api.uploads.isEmpty())
    }

    @Test
    fun recovery_blankCode_neverHitsWire() {
        val final = runBlocking {
            coordinator().recoverWithCode(session, server, "   ", RecoveryMode.NewDevice)
        }
        assertEquals(BootstrapFinal.Failed(FailKind.REJECTED), final)
        assertEquals(0, api.recoverCalls)
        assertEquals(0, api.bindCalls)
    }

    @Test
    fun approvalView_splitsSelfPendingAndActive() {
        val self = DeviceRecord(
            deviceId = "self-1111-2222-3333-444455555555",
            registrationId = 4242,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VsZg==",
            signedPrekeyId = 1,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 100,
        )
        val otherPending = pendingRow("cGVuZGluZw==").copy(deviceId = "pend-1111-2222-3333-444455555555")
        val otherActive = self.copy(deviceId = "act-1111-2222-3333-444455555555", signalDeviceId = 3)
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(self, otherPending, otherActive)) }
        metadata.writeAdopted(
            com.samvaad.android.enroll.AdoptedDevice(
                deviceId = self.deviceId,
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = "c2VsZg==",
                signedPrekeyId = 1,
                kyberPrekeyId = 1,
                otpkHighWaterMark = 100,
                roleHint = "PRIMARY",
                statusHint = "ACTIVE",
                identityHandleId = "11111111-2222-3333-4444-555555555555",
                signedHandleId = "22222222-2222-3333-4444-555555555555",
                kyberHandleId = "33333333-2222-3333-4444-555555555555",
                otpkHandleIds = listOf("44444444-2222-3333-4444-555555555555"),
                codesAcknowledged = true,
            )
        )

        val loaded = runBlocking { coordinator().loadApprovalView(session, server) }
        val view = (loaded as ApprovalLoad.Ready).view

        assertEquals(self.deviceId, view.selfDeviceId)
        assertTrue(view.selfActive)
        assertEquals(listOf(otherPending), view.pending)
        assertEquals(listOf(otherActive), view.active)
    }

    @Test
    fun approve_success_convergesThroughList() {
        val target = pendingRow("cGVuZGluZw==")
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(target.copy(status = "ACTIVE"))) }
        api.approveHandler = { target.copy(status = "ACTIVE") }

        val outcome = runBlocking { coordinator().approvePendingDevice(session, server, target.deviceId) }

        val approved = outcome as ApproveOutcome.Approved
        assertTrue(approved.deviceLabel.contains("#2"))
        assertEquals(1, api.approveCalls)
    }

    @Test
    fun approve_denied_mapsToDenied() {
        api.approveHandler = { throw EnrollException.ServerRejected() }

        val outcome = runBlocking { coordinator().approvePendingDevice(session, server, "any-id") }

        assertEquals(ApproveOutcome.Denied, outcome)
        // Denial converges without a follow-up list.
        assertEquals(0, api.listCalls)
    }

    @Test
    fun approve_unknown_convergesToGone() {
        api.approveHandler = { throw EnrollException.NotFound() }
        api.listHandler = { DeviceList("RECOVERY_REQUIRED", emptyList()) }

        val outcome = runBlocking { coordinator().approvePendingDevice(session, server, "gone-id") }

        assertEquals(ApproveOutcome.Gone, outcome)
    }

    @Test
    fun concurrentRecovery_secondCallFailsFast() {
        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        api.approveHandler = {
            entered.countDown()
            assertTrue(gate.await(10, TimeUnit.SECONDS))
            pendingRow("eA==", "ACTIVE")
        }
        api.listHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(pendingRow("eA==", "ACTIVE")))
        }
        val shared = coordinator()
        val targetId = "aaaaaaaa-2222-3333-4444-555555555555"
        val first = kotlinx.coroutines.CoroutineScope(Dispatchers.IO).async {
            shared.approvePendingDevice(session, server, targetId)
        }
        // Wait until the first call holds the coordinator lock.
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        val second = runBlocking { shared.approvePendingDevice(session, server, targetId) }
        assertEquals(ApproveOutcome.Failed(FailKind.ALREADY_RUNNING), second)
        gate.countDown()
        assertTrue(runBlocking { first.await() } is ApproveOutcome.Approved)
    }

    @Test
    fun pending_reentry_convergesThroughList() {
        seedPending()
        val adoptedId = metadata.readAdopted()!!.deviceId
        // Fresh process: new coordinator, same persisted metadata.
        val reentered = EnrollmentCoordinator(
            api = api,
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, keys),
        )
        val final = runBlocking { reentered.runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.PendingApproval)
        assertEquals(adoptedId, metadata.readAdopted()!!.deviceId)
    }
}
