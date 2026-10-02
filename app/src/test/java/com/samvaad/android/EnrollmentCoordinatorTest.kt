package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FailKind
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.OneTimePrekeyUpload
import java.io.File
import java.io.IOException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Coordinator tests with a scripted fake API and real crypto/vault
 * (ephemeral AES key standing in for the Keystore key; custody itself is
 * covered by instrumented tests). No network, no UI, no enrollment of
 * real devices. Session/token values are random test strings.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class EnrollmentCoordinatorTest {

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
        var enrollHandler: (EnrollRequest) -> EnrollResult =
            { throw AssertionError("unexpected enroll") }
        var uploadHandler: (String, List<OneTimePrekeyUpload>) -> Unit = { _, _ -> }
        var listHandler: () -> DeviceList =
            { DeviceList("ENROLLED_ACTIVE", emptyList()) }
        var enrollCalls = 0
        val posted = mutableListOf<EnrollRequest>()
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
        ): DeviceList = listHandler()

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
    }

    private lateinit var context: Context
    private lateinit var api: FakeApi
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

    private fun deviceRecord(
        req: EnrollRequest,
        status: String = "ACTIVE",
        role: String = "PRIMARY",
    ) = DeviceRecord(
        deviceId = "22222222-2222-3333-4444-555555555555",
        registrationId = req.registrationId,
        signalDeviceId = 1,
        deviceIdentityPublicKey = req.deviceIdentityPublicKey,
        signedPrekeyId = req.signedPrekeyId,
        deviceRole = role,
        status = status,
        availablePrekeys = 0,
    )

    private fun deviceRecordByIdentity(
        identityB64: String,
        status: String = "ACTIVE",
        role: String = "PRIMARY",
        availablePrekeys: Long = 0,
    ) = DeviceRecord(
        deviceId = "22222222-2222-3333-4444-555555555555",
        registrationId = 4242,
        signalDeviceId = 1,
        deviceIdentityPublicKey = identityB64,
        signedPrekeyId = 1,
        deviceRole = role,
        status = status,
        availablePrekeys = availablePrekeys,
    )

    private fun codes(n: Int = 25): List<String> =
        List(n) { i -> "code-${i}-test-value" }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        api = FakeApi()
        metadata = FileDeviceMetadataStore(context)
        keys = EphemeralKeys()
    }

    @Test
    fun firstBootstrap_success_uploads100_andShowsCodesOnce() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }

        val ack = final as BootstrapFinal.AwaitingCodesAck
        assertEquals(25, ack.codes.size)
        assertEquals(1, api.enrollCalls)
        assertEquals(1, api.uploads.size)
        assertEquals(100, api.uploads.single().second.size)
        // Marker cleared only after successful provisioning.
        assertTrue(metadata.readAttempt() == null)
        val adopted = metadata.readAdopted()!!
        assertEquals("22222222-2222-3333-4444-555555555555", adopted.deviceId)
        assertEquals(100, adopted.otpkHighWaterMark)
        assertFalse(adopted.codesAcknowledged)
        // Ack records the flag; codes live only in the transient result.
        assertTrue(coordinator().acknowledgeCodes())
        // Adopted path needs no new POST: refresh via list returns Active.
        val adoptedIdentity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRecordByIdentity(adoptedIdentity, availablePrekeys = 100))
            )
        }
        val after = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(after is BootstrapFinal.Active)
        assertEquals(1, api.enrollCalls)
        assertTrue((after as BootstrapFinal.Active).codesAcknowledged)
    }

    @Test
    fun duplicateSubmit_secondCallFailsFastWithSinglePost() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        api.enrollHandler = { req ->
            entered.countDown()
            assertTrue(
                "enroll handler timed out waiting for release",
                release.await(10, java.util.concurrent.TimeUnit.SECONDS)
            )
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        val coord = coordinator()
        runBlocking {
            // Background dispatcher: the gated handler blocks its thread,
            // so the second call must run elsewhere to observe the guard.
            val first = async(Dispatchers.IO) { coord.runBootstrap(session, server) }
            // Bounded wait for the first call to reach the enroll handler —
            // no fixed sleep, explicit failure instead of an indefinite hang.
            assertTrue(
                "first bootstrap did not reach enroll",
                withContext(Dispatchers.IO) {
                    entered.await(10, java.util.concurrent.TimeUnit.SECONDS)
                }
            )
            val second = coord.runBootstrap(session, server)
            assertTrue(second is BootstrapFinal.Failed)
            assertEquals(
                FailKind.ALREADY_RUNNING,
                (second as BootstrapFinal.Failed).kind
            )
            release.countDown()
            val done = first.await()
            assertTrue(done is BootstrapFinal.AwaitingCodesAck)
        }
        assertEquals(1, api.enrollCalls)
    }

    @Test
    fun cryptoMaterial_reusedAfterTransportFailure_noRegeneration() {
        var attempts = 0
        api.enrollHandler = { req ->
            if (++attempts == 1) throw IOException("boom")
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        val first = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(first is BootstrapFinal.Failed)
        assertEquals(FailKind.TRANSPORT_RETRYABLE, (first as BootstrapFinal.Failed).kind)
        // Attempt marker retained.
        val markerIdentity = metadata.readAttempt()!!.identityPublicKeyB64

        val second = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(second is BootstrapFinal.AwaitingCodesAck)
        // Same identity reused: exactly one POST per attempt, same material.
        assertEquals(2, api.enrollCalls)
        assertEquals(markerIdentity, api.posted[0].deviceIdentityPublicKey)
        assertEquals(api.posted[0].deviceIdentityPublicKey, api.posted[1].deviceIdentityPublicKey)
    }

    @Test
    fun attemptMarker_createdBeforePost() {
        api.enrollHandler = { req ->
            assertTrue(metadata.readAttempt() != null)
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        runBlocking { coordinator().runBootstrap(session, server) }
    }

    @Test
    fun pendingEnrollment_doesNotUpload() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req, status = "PENDING"), "ENROLLED_ACTIVE", null)
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.PendingApproval)
        assertTrue(api.uploads.isEmpty())
        // Marker retained for the future approval flow.
        assertTrue(metadata.readAttempt() != null)
    }

    @Test
    fun conflict_triggersReconcileAndAdoptsExactMatch() {
        var posted = 0
        api.enrollHandler = { posted++; throw EnrollException.Conflict() }
        // Reconcile finds the already-committed device: adopt, no second POST.
        api.listHandler = {
            // Identity unknown until the first POST attempt writes the marker.
            val attempt = metadata.readAttempt()
            if (posted == 0 || attempt == null) {
                DeviceList("ENROLLED_ACTIVE", emptyList())
            } else {
                DeviceList("ENROLLED_ACTIVE", listOf(deviceRecordByIdentity(attempt.identityPublicKeyB64)))
            }
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        // Adopted via reconcile: no codes in hand → Active-unacked.
        assertTrue(final is BootstrapFinal.Active)
        assertFalse((final as BootstrapFinal.Active).codesAcknowledged)
        assertEquals(1, api.enrollCalls)
        assertEquals(1, api.uploads.size)
        assertEquals(100, api.uploads.single().second.size)
    }

    @Test
    fun reconcile_multipleMatches_failsClosedWithoutPost() {
        // Seed local material via a transport failure, then present doppelgangers.
        api.enrollHandler = { throw IOException("boom") }
        runBlocking { coordinator().runBootstrap(session, server) }
        val identity = metadata.readAttempt()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList(
                "ENROLLED_ACTIVE",
                listOf(deviceRecordByIdentity(identity), deviceRecordByIdentity(identity))
            )
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.ReconciliationRequired)
        assertEquals(1, api.enrollCalls) // no second POST
    }

    @Test
    fun serverIdentityMismatch_failsClosed() {
        api.enrollHandler = {
            EnrollResult(deviceRecordByIdentity("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "NEVER_ENROLLED", codes())
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.Failed)
        assertEquals(FailKind.IDENTITY_MISMATCH, (final as BootstrapFinal.Failed).kind)
        // Nothing adopted on mismatch.
        assertTrue(metadata.readAdopted() == null)
    }

    @Test
    fun recoveryRequired_typedState() {
        api.enrollHandler = { throw EnrollException.RecoveryRequired() }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.RecoveryRequired)
    }

    @Test
    fun unauthorized_failedState() {
        api.enrollHandler = { throw EnrollException.Unauthorized() }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertEquals(FailKind.UNAUTHORIZED, (final as BootstrapFinal.Failed).kind)
    }

    @Test
    fun otpkBatch_exactMapping_uniqueIds_publics() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        runBlocking { coordinator().runBootstrap(session, server) }
        val batch = api.uploads.single().second
        assertEquals(100, batch.size)
        val ids = batch.map { it.prekeyId }
        assertEquals(100, ids.toSet().size)
        batch.forEach {
            val decoded = java.util.Base64.getDecoder().decode(it.publicKey)
            assertEquals(33, decoded.size)
        }
        // And they match the sealed vault material exactly.
        val marker = metadata.readAdopted()!!
        assertEquals(ids.max(), marker.otpkHighWaterMark)
    }

    @Test
    fun secrets_neverPersisted_neverInMetadataOrVaultFiles() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        val shown = (final as BootstrapFinal.AwaitingCodesAck).codes
        coordinator().acknowledgeCodes()
        val haystacks = allStoredBytes()
        shown.forEach { code ->
            haystacks.forEach { bytes ->
                assertFalse(contains(bytes, code.toByteArray(Charsets.UTF_8)))
            }
        }
        // Auth session values never persisted either.
        listOf(session.accessToken, session.refreshToken, session.sessionId).forEach { secret ->
            haystacks.forEach { bytes ->
                assertFalse(contains(bytes, secret.toByteArray(Charsets.UTF_8)))
            }
        }
    }

    @Test
    fun localMetadata_doesNotBecomeAuthority_serverWins() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        runBlocking { coordinator().runBootstrap(session, server) }
        coordinator().acknowledgeCodes()
        // Server now reports the device as non-ACTIVE: refresh must follow it.
        val identity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(deviceRecordByIdentity(identity, status = "REVOKED")))
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.PendingApproval)
        assertEquals("REVOKED", metadata.readAdopted()!!.statusHint)
        // No OTPK upload against a non-ACTIVE device.
        assertEquals(1, api.uploads.size) // only the first bootstrap upload
    }

    @Test
    fun reconcile_listFailure_mapsToRetryable() {
        // The reconcile list call runs before any POST, even on a fresh
        // device: fail it and assert no enrollment is attempted.
        api.listHandler = { throw IOException("boom") }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.Failed)
        assertEquals(FailKind.TRANSPORT_RETRYABLE, (final as BootstrapFinal.Failed).kind)
        assertEquals(0, api.enrollCalls)
    }

    @Test
    fun reconcile_pendingMatch_stopsWithoutUpload() {
        api.enrollHandler = { throw IOException("boom") }
        runBlocking { coordinator().runBootstrap(session, server) }
        val identity = metadata.readAttempt()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(deviceRecordByIdentity(identity, status = "PENDING")))
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.PendingApproval)
        assertEquals(1, api.enrollCalls) // no second POST
        assertTrue(api.uploads.isEmpty()) // no upload to a non-ACTIVE device
    }

    @Test
    fun acknowledgeCodes_withoutAdopted_returnsFalse() {
        assertFalse(coordinator().acknowledgeCodes())
    }

    @Test
    fun adopted_keysGone_failClosedCryptoUnavailable() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        runBlocking { coordinator().runBootstrap(session, server) }
        coordinator().acknowledgeCodes()
        // Simulate out-of-band vault loss with metadata surviving.
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        val identity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(deviceRecordByIdentity(identity)))
        }
        // Fresh adapter (restart-like): nothing in memory to fall back on.
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.ReconciliationRequired)
    }

    @Test
    fun adopted_zeroPrekeys_finishesProvisioningWithSameBatch() {
        api.enrollHandler = { req ->
            EnrollResult(deviceRecord(req), "NEVER_ENROLLED", codes())
        }
        runBlocking { coordinator().runBootstrap(session, server) }
        coordinator().acknowledgeCodes()
        assertEquals(1, api.uploads.size)
        // Server still shows zero prekeys (crash landed pre-upload): the
        // same sealed batch is uploaded, no regeneration, no new POST.
        val identity = metadata.readAdopted()!!.identityPublicKeyB64
        api.listHandler = {
            DeviceList("ENROLLED_ACTIVE", listOf(deviceRecordByIdentity(identity)))
        }
        val final = runBlocking { coordinator().runBootstrap(session, server) }
        assertTrue(final is BootstrapFinal.Active)
        assertEquals(1, api.enrollCalls)
        assertEquals(2, api.uploads.size)
        assertEquals(
            api.uploads[0].second.map { it.prekeyId },
            api.uploads[1].second.map { it.prekeyId },
        )
    }

    private fun allStoredBytes(): List<ByteArray> {
        val roots = listOf(
            File(context.noBackupFilesDir, "device-metadata"),
            File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR),
        )
        return roots.flatMap { dir ->
            dir.walkTopDown().filter { it.isFile }.map { it.readBytes() }.toList()
        }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
