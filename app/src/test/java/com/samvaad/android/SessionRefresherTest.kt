package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
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
 * Refresher + logout + enrollment-interplay tests. Fake [AuthApi] scripts
 * server behavior; the store is real (ephemeral AES key standing in for
 * the Keystore key). No network, no UI.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SessionRefresherTest {

    private class EphemeralKeys(var present: Boolean = true) : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = if (present) key else null
    }

    private class FakeAuth : AuthApi {
        var loginHandler: (LoginRequest) -> AuthSession =
            { throw AssertionError("unexpected login") }
        var refreshHandler: (String, String) -> RefreshedSession =
            { _, _ -> throw AssertionError("unexpected refresh") }
        var logoutHandler: (String, String) -> Unit = { _, _ -> }
        val refreshCalls = AtomicInteger(0)
        val logoutCalls = AtomicInteger(0)

        override suspend fun login(request: LoginRequest): AuthSession =
            loginHandler(request)

        override suspend fun refresh(serverAddress: String, refreshToken: String): RefreshedSession {
            refreshCalls.incrementAndGet()
            return refreshHandler(serverAddress, refreshToken)
        }

        override suspend fun logout(serverAddress: String, accessToken: String) {
            logoutCalls.incrementAndGet()
            logoutHandler(serverAddress, accessToken)
        }
    }

    private lateinit var context: Context
    private lateinit var auth: FakeAuth
    private lateinit var keys: EphemeralKeys
    private lateinit var store: FileSessionStore

    private val server = "https://example.test:8080"

    private fun refresher(): SessionRefresher =
        SessionRefresher(auth, FileSessionStore(context, keys))

    private fun seed(
        refreshToken: String = "refresh-token-1",
        sessionId: String = "11111111-2222-3333-4444-555555555555",
    ) {
        store.save(
            com.samvaad.android.session.PersistedSession(
                serverAddress = server,
                identifier = "alice",
                refreshToken = refreshToken,
                sessionId = sessionId,
                refreshExpiresAtEpochMillis = System.currentTimeMillis() +
                    30L * 24 * 60 * 60 * 1000,
            )
        )
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        auth = FakeAuth()
        keys = EphemeralKeys()
        store = FileSessionStore(context, keys)
    }

    @Test
    fun restore_validRecord_refreshesAndRotatesAtomically() {
        seed()
        auth.refreshHandler = { _, presented ->
            assertEquals("refresh-token-1", presented)
            RefreshedSession("access-2", "refresh-token-2", "11111111-2222-3333-4444-555555555555")
        }
        val outcome = runBlocking { refresher().restoreSession() }
        val authenticated = outcome as SessionRefresher.RestoreOutcome.Authenticated
        assertEquals("access-2", authenticated.session.accessToken)
        assertEquals("refresh-token-2", authenticated.session.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", authenticated.session.sessionId)
        assertEquals(server, authenticated.serverAddress)
        // Old token gone from durable storage; only the rotated one remains.
        val raw = String(FileSessionStore.rawFile(context).readBytes(), Charsets.UTF_8)
        assertFalse(raw.contains("refresh-token-1"))
    }

    @Test
    fun restore_noRecord_returnsNoStoredSession() {
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.NoStoredSession)
        assertEquals(0, auth.refreshCalls.get())
    }

    @Test
    fun restore_rejectedRefresh_wipesRecord() {
        seed()
        auth.refreshHandler = { _, _ -> throw RefreshRejectedException() }
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.SessionExpired)
        assertFalse(FileSessionStore.rawFile(context).exists())
    }

    @Test
    fun restore_expiredRecord_skipsNetwork() {
        store.save(
            com.samvaad.android.session.PersistedSession(
                serverAddress = server,
                identifier = "alice",
                refreshToken = "stale-token",
                sessionId = "11111111-2222-3333-4444-555555555555",
                refreshExpiresAtEpochMillis = 1L,
            )
        )
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.SessionExpired)
        assertEquals(0, auth.refreshCalls.get())
        assertFalse(FileSessionStore.rawFile(context).exists())
    }

    @Test
    fun restore_corruptRecord_failsClosed() {
        FileSessionStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeBytes(byteArrayOf(0x01, 0x02))
        }
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.SessionExpired)
    }

    @Test
    fun restore_missingKey_failsClosedWithoutWiping() {
        seed()
        keys.present = false
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.SessionExpired)
        // Nothing proven about the file: leave it alone.
        assertTrue(FileSessionStore.rawFile(context).exists())
    }

    @Test
    fun restore_transportFailure_propagatesWithoutWiping() {
        seed()
        auth.refreshHandler = { _, _ -> throw IOException("boom") }
        val outcome = runBlocking { refresher().restoreSession() }
        assertTrue(outcome is SessionRefresher.RestoreOutcome.Unreachable)
        assertTrue(FileSessionStore.rawFile(context).exists())
    }

    @Test
    fun restore_concurrentCallers_singleRefresh() {
        seed()
        val entered = CountDownLatch(1)
        val attached = CountDownLatch(3)
        val release = CountDownLatch(1)
        auth.refreshHandler = { _, _ ->
            entered.countDown()
            // Wait until every follower has reached its restore call before
            // allowing completion: their mutex election is then uncontended
            // and immediate, while this owner still holds the refresh open.
            assertTrue(attached.await(10, TimeUnit.SECONDS))
            assertTrue(release.await(10, TimeUnit.SECONDS))
            RefreshedSession("access-2", "refresh-token-2", "11111111-2222-3333-4444-555555555555")
        }
        val refresher = refresher()
        val results = runBlocking {
            val first = async(Dispatchers.IO) { refresher.restoreSession() }
            assertTrue(
                withContext(Dispatchers.IO) { entered.await(10, TimeUnit.SECONDS) }
            )
            val rest = (1..3).map {
                async(Dispatchers.IO) {
                    attached.countDown()
                    refresher.restoreSession()
                }
            }
            // All followers are at the call before the owner may complete.
            assertTrue(
                withContext(Dispatchers.IO) { attached.await(10, TimeUnit.SECONDS) }
            )
            release.countDown()
            (listOf(first) + rest).awaitAll()
        }
        assertEquals(1, auth.refreshCalls.get())
        results.forEach {
            val authenticated = it as SessionRefresher.RestoreOutcome.Authenticated
            assertEquals("access-2", authenticated.session.accessToken)
        }
    }

    @Test
    fun persistLogin_savesBundle() {
        val session = AuthSession("alice", "access-1", "refresh-1", "11111111-2222-3333-4444-555555555555")
        runBlocking { refresher().persistLogin(server, session) }
        val loaded = FileSessionStore(context, keys).load()!!
        assertEquals(server, loaded.serverAddress)
        assertEquals("alice", loaded.identifier)
        assertEquals("refresh-1", loaded.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", loaded.sessionId)
        assertTrue(loaded.refreshExpiresAtEpochMillis > System.currentTimeMillis())
    }

    @Test
    fun logout_attemptsServerThenWipesLocally() {
        seed()
        val session = AuthSession("alice", "access-1", "refresh-token-1", "11111111-2222-3333-4444-555555555555")
        var loggedOutWith: String? = null
        auth.logoutHandler = { _, access -> loggedOutWith = access }
        runBlocking { refresher().logout(server, session) }
        assertEquals("access-1", loggedOutWith)
        assertEquals(1, auth.logoutCalls.get())
        assertNull(FileSessionStore(context, keys).load())
    }

    @Test
    fun logout_offline_stillWipesLocally() {
        seed()
        auth.logoutHandler = { _, _ -> throw IOException("boom") }
        val session = AuthSession("alice", "access-1", "refresh-token-1", "11111111-2222-3333-4444-555555555555")
        runBlocking { refresher().logout(server, session) }
        assertNull(FileSessionStore(context, keys).load())
    }

    @Test
    fun logout_preservesCryptoAndDeviceState() {        // Seed vault + device metadata markers (contents irrelevant here;
        // the point is logout never touches those directories).
        val vaultDir = File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR)
        val metaDir = File(context.noBackupFilesDir, "device-metadata")
        vaultDir.mkdirs()
        metaDir.mkdirs()
        File(vaultDir, "sentinel.bin").writeBytes(byteArrayOf(1, 2, 3))
        File(metaDir, "sentinel.json").writeText("{}", Charsets.UTF_8)
        seed()
        val session = AuthSession("alice", "access-1", "refresh-token-1", "11111111-2222-3333-4444-555555555555")
        runBlocking { refresher().logout(server, session) }
        assertTrue(File(vaultDir, "sentinel.bin").exists())
        assertTrue(File(metaDir, "sentinel.json").exists())
        assertNull(FileSessionStore(context, keys).load())
    }

    @Test
    fun enrollmentInterplay_restoredSessionContinuesProvisioning() {
        // Death after enroll-commit, before OTPK upload: vault + adopted
        // metadata survive; the SAME logical session refreshes back.
        val adapter = AndroidSignalAdapter()
        val vault = AndroidCryptoVault(context, keys)
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..100).map { adapter.generateOneTimePrekey(it) }
        val identityB64 = java.util.Base64.getEncoder().encodeToString(identity.publicKey)
        vault.seal(identity.privateHandle, com.samvaad.android.crypto.CryptoRecordKind.IDENTITY,
            adapter.exportRecord(identity.privateHandle))
        vault.seal(signed.privateHandle, com.samvaad.android.crypto.CryptoRecordKind.SIGNED_PREKEY,
            adapter.exportRecord(signed.privateHandle))
        vault.seal(kyber.privateHandle, com.samvaad.android.crypto.CryptoRecordKind.KYBER_PREKEY,
            adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            vault.seal(it.privateHandle, com.samvaad.android.crypto.CryptoRecordKind.ONE_TIME_PREKEY,
                adapter.exportRecord(it.privateHandle))
        }
        val metadata = FileDeviceMetadataStore(context)
        metadata.writeAdopted(
            com.samvaad.android.enroll.AdoptedDevice(
                deviceId = "22222222-2222-3333-4444-555555555555",
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = identityB64,
                signedPrekeyId = 1,
                kyberPrekeyId = 1,
                otpkHighWaterMark = 100,
                roleHint = "PRIMARY",
                statusHint = "ACTIVE",
                identityHandleId = identity.privateHandle.id.toString(),
                signedHandleId = signed.privateHandle.id.toString(),
                kyberHandleId = kyber.privateHandle.id.toString(),
                otpkHandleIds = otpks.map { it.privateHandle.id.toString() },
                codesAcknowledged = false,
            )
        )
        seed(refreshToken = "refresh-bound-1", sessionId = "22222222-3333-4444-5555-666666666666")
        auth.refreshHandler = { _, _ ->
            RefreshedSession("access-bound-2", "refresh-bound-2", "22222222-3333-4444-5555-666666666666")
        }
        var uploaded: List<OneTimePrekeyUpload>? = null
        val e2ee = object : E2eeDeviceApi {
            override suspend fun enroll(
                session: AuthSession, serverAddress: String,
                request: EnrollRequest,
            ): EnrollResult = throw AssertionError("must not re-enroll")

            override suspend fun uploadOneTimePrekeys(
                session: AuthSession, serverAddress: String, deviceId: String,
                batch: List<OneTimePrekeyUpload>,
            ) {
                // The restored session is the SAME bound session.
                assertEquals("22222222-3333-4444-5555-666666666666", session.sessionId)
                assertEquals("22222222-2222-3333-4444-555555555555", deviceId)
                uploaded = batch
            }

            override suspend fun listDevices(
                session: AuthSession, serverAddress: String,
            ): DeviceList = DeviceList(
                "ENROLLED_ACTIVE",
                listOf(
                    DeviceRecord(
                        deviceId = "22222222-2222-3333-4444-555555555555",
                        registrationId = 4242,
                        signalDeviceId = 1,
                        deviceIdentityPublicKey = identityB64,
                        signedPrekeyId = 1,
                        deviceRole = "PRIMARY",
                        status = "ACTIVE",
                        availablePrekeys = 0,
                    )
                ),
            )

            override suspend fun listRecipientDevices(
                session: AuthSession, serverAddress: String, username: String,
            ): List<com.samvaad.android.enroll.RecipientDeviceRecord> =
                throw AssertionError("no discovery in this slice")

            override suspend fun claimOneTimePrekey(
                session: AuthSession, serverAddress: String, deviceId: String,
                requestId: java.util.UUID,
            ): com.samvaad.android.enroll.ClaimedDeviceBundle =
                throw AssertionError("no discovery in this slice")

            override suspend fun submitMessage(
                session: AuthSession, serverAddress: String,
                requestId: java.util.UUID,
                envelopes: List<com.samvaad.android.enroll.MessageEnvelopeSubmit>,
            ): com.samvaad.android.enroll.SubmitMessageResult =
                throw AssertionError("no submission in this slice")

            override suspend fun fetchMailbox(
                session: AuthSession, serverAddress: String, limit: Int,
            ): List<com.samvaad.android.enroll.MailboxItem> =
                throw AssertionError("no inbox in this slice")

            override suspend fun ackMailbox(
                session: AuthSession, serverAddress: String,
                messageIds: List<java.util.UUID>,
            ): Int = throw AssertionError("no inbox in this slice")
        }
        // Fresh instances throughout: restart-like conditions.
        val restored = runBlocking { SessionRefresher(auth, FileSessionStore(context, keys)).restoreSession() }
            as SessionRefresher.RestoreOutcome.Authenticated
        val coordinator = EnrollmentCoordinator(
            api = e2ee,
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, keys),
        )
        val outcome = runBlocking {
            coordinator.runBootstrap(restored.session, restored.serverAddress)
        }
        assertTrue(outcome is BootstrapFinal.Active)
        assertEquals(100, uploaded!!.size)
    }

    @Test
    fun exceptionMessages_carryNoTokens() {
        // Rejection carries no payload by construction; the wipe removes
        // the only durable copy.
        assertNull(RefreshRejectedException().message)
        seed(refreshToken = "secret-refresh-xyz")
        auth.refreshHandler = { _, _ -> throw RefreshRejectedException() }
        runBlocking { refresher().restoreSession() }
        assertNull(FileSessionStore(context, keys).load())
    }
}
