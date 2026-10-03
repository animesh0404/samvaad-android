package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.RecordEnvelopeCodec
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.ClaimedOneTimePrekey
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionMetadataStore
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Outbound session-establishment tests with a scripted fake API and REAL
 * crypto (adapter + vault sealed under an ephemeral AES key standing in
 * for the Keystore key). No network, no UI.
 *
 * Claim counting is the observable proof of the claim-burn and reuse
 * invariants: reuse performs zero claims, failure-then-retry performs a
 * fresh claim, and concurrent establishment performs exactly one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SessionEstablisherTest {

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key

        fun dropKey() {
            key = null
        }
    }

    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> = { emptyList() }
        var claimHandler: suspend (String, UUID) -> ClaimedDeviceBundle =
            { _, _ -> throw AssertionError("unexpected claim") }
        var directoryCalls = 0
        var claimCalls = 0
        val claimRequestIds = mutableListOf<UUID>()

        override suspend fun enroll(
            session: AuthSession,
            serverAddress: String,
            request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment in this slice")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = throw AssertionError("no upload in this slice")

        override suspend fun listDevices(
            session: AuthSession,
            serverAddress: String,
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
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): List<RecipientDeviceRecord> {
            directoryCalls++
            return directoryHandler(username)
        }

        override suspend fun claimOneTimePrekey(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            requestId: UUID,
        ): ClaimedDeviceBundle {
            claimCalls++
            claimRequestIds.add(requestId)
            return claimHandler(deviceId, requestId)
        }

        override suspend fun submitMessage(
            session: AuthSession,
            serverAddress: String,
            requestId: UUID,
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

    /** Remote device fixture: real libsignal public material as wire B64. */
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

    private fun remoteFixture(signalDeviceId: Int = 2, registrationId: Int = 7001): RemoteFixture {
        val remote = AndroidSignalAdapter()
        val identity = remote.generateIdentity()
        val signed = remote.generateSignedPrekey(identity, 11)
        val kyber = remote.generateKyberPrekey(identity, 21)
        val otk = remote.generateOneTimePrekey(101)
        return RemoteFixture(
            registrationId = registrationId,
            signalDeviceId = signalDeviceId,
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

    private fun recipientOf(deviceId: String, f: RemoteFixture, kyber: Boolean = true) =
        RecipientDeviceRecord(
            deviceId = deviceId,
            registrationId = f.registrationId,
            signalDeviceId = f.signalDeviceId,
            deviceIdentityPublicKey = f.identityB64,
            signedPrekeyId = f.signedId,
            signedPrekey = f.signedB64,
            signedPrekeySignature = f.signedSigB64,
            hasAvailableOneTimePrekey = true,
            deviceRole = "COMPANION",
            kyberPrekeyId = if (kyber) f.kyberId else null,
            kyberPrekey = if (kyber) f.kyberB64 else null,
            kyberPrekeySignature = if (kyber) f.kyberSigB64 else null,
        )

    private fun claimOf(deviceId: String, f: RemoteFixture, withOtk: Boolean = true) =
        ClaimedDeviceBundle(
            deviceId = deviceId,
            registrationId = f.registrationId,
            signalDeviceId = f.signalDeviceId,
            deviceIdentityPublicKey = f.identityB64,
            signedPrekeyId = f.signedId,
            signedPrekey = f.signedB64,
            signedPrekeySignature = f.signedSigB64,
            oneTimePrekey = if (withOtk) ClaimedOneTimePrekey(f.otkId, f.otkB64) else null,
            deviceRole = "COMPANION",
            kyberPrekeyId = f.kyberId,
            kyberPrekey = f.kyberB64,
            kyberPrekeySignature = f.kyberSigB64,
        )

    private lateinit var context: Context
    private lateinit var api: FakeApi
    private lateinit var keys: EphemeralKeys
    private lateinit var adapter: AndroidSignalAdapter
    private lateinit var identityVault: AndroidCryptoVault
    private lateinit var sessionVault: AndroidCryptoVault
    private lateinit var localMeta: FileDeviceMetadataStore
    private lateinit var sessionMeta: FileSessionMetadataStore

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val server = "https://example.test:8080"

    private fun establisher() = SessionEstablisher(
        api = api,
        localMetadata = localMeta,
        sessions = sessionMeta,
        adapter = adapter,
        identityVault = identityVault,
        sessionVault = sessionVault,
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
        identityVault = AndroidCryptoVault(context, keys)
        sessionVault = AndroidCryptoVault(context, keys, FileSessionMetadataStore.SUBDIR)
        localMeta = FileDeviceMetadataStore(context)
        sessionMeta = FileSessionMetadataStore(context)
    }

    /** Seal a real adopted local device; returns its handle id. */
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
        val adopted = AdoptedDevice(
            deviceId = "11111111-1111-1111-1111-111111111111",
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
        localMeta.writeAdopted(adopted)
        return adopted
    }

    private fun sessionBlobFile(deviceId: String): File {
        val handle = SessionEstablisher.sessionHandleFor(deviceId)
        return File(
            File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR),
            "${CryptoRecordKind.SESSION.name}_${handle.id}.svlt",
        )
    }

    // ---- happy paths ----

    @Test
    fun fresh_withOtk_establishesPersistsAndReuses() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f, withOtk = true) }

        val first = runBlocking { establisher().establish(session, server, "bob", deviceId) }
        val entry = (first as SessionEstablishResult.Established).entry
        assertFalse(first.reused)
        assertEquals(EstablishedVia.WITH_OTPK, entry.establishedVia)
        assertEquals(deviceId, entry.remoteDeviceId)
        assertEquals("bob", entry.remoteUsername)
        assertEquals(2, entry.remoteSignalDeviceId)
        assertEquals(7001, entry.remoteRegistrationId)
        assertEquals(f.identityB64, entry.remoteIdentityPublicKeyB64)

        // Vault proof: SESSION-kind envelope in signal-sessions/, ready record.
        val blob = sessionBlobFile(deviceId)
        assertTrue(blob.isFile)
        val parsed = RecordEnvelopeCodec.parse(blob.readBytes())
        assertEquals(CryptoRecordKind.SESSION, parsed.kind)
        val info = adapter.inspectSession(
            sessionVault.unseal(
                SessionEstablisher.sessionHandleFor(deviceId), CryptoRecordKind.SESSION
            )
        )
        assertEquals(f.identityB64, SpikeCryptoMaterial.encodeBase64(info.remoteIdentityBytes))

        // Reuse: no second directory hit, no second claim, no second process.
        val second = runBlocking { establisher().establish(session, server, "bob", deviceId) }
        assertTrue((second as SessionEstablishResult.Established).reused)
        assertEquals(1, api.directoryCalls)
        assertEquals(1, api.claimCalls)
    }

    @Test
    fun fallback_withoutOtk_establishesSignedFallback() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f, withOtk = false) }

        val result = runBlocking { establisher().establish(session, server, "bob", deviceId) }
        val entry = (result as SessionEstablishResult.Established).entry
        assertEquals(EstablishedVia.SIGNED_FALLBACK, entry.establishedVia)
        // The fallback session still encrypts (probe via the real cipher).
        val adopted = localMeta.readAdopted()!!
        val local = restoreLocalForProbe(requireNotNull(adopted.identityHandleId))
        val wire = adapter.probeEncrypt(
            local, adopted.registrationId,
            sessionVault.unseal(SessionEstablisher.sessionHandleFor(deviceId), CryptoRecordKind.SESSION),
            SpikeCryptoMaterial.decodeBase64(entry.remoteIdentityPublicKeyB64),
            "bob", 2, "probe".toByteArray(),
        )
        assertTrue(wire.isNotEmpty())
    }

    private fun restoreLocalForProbe(handleId: String) =
        when (val r = adapter.restoreRecord(
            SpikeCryptoMaterial.SealedHandle(
                UUID.fromString(handleId), CryptoRecordKind.IDENTITY
            ),
            identityVault.unseal(
                SpikeCryptoMaterial.SealedHandle(
                    UUID.fromString(handleId), CryptoRecordKind.IDENTITY
                ),
                CryptoRecordKind.IDENTITY,
            ),
        )) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> r.value
            else -> throw AssertionError("unexpected kind")
        }

    @Test
    fun multipleDevices_requireExactSelection() {
        sealLocalDevice()
        val devA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        val devB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        val fa = remoteFixture(signalDeviceId = 1)
        val fb = remoteFixture(signalDeviceId = 2)
        api.directoryHandler = { listOf(recipientOf(devA, fa), recipientOf(devB, fb)) }
        api.claimHandler = { id, _ ->
            if (id == devB) claimOf(devB, fb) else throw AssertionError("wrong device claimed: $id")
        }
        val result = runBlocking { establisher().establish(session, server, "bob", devB) }
        val entry = (result as SessionEstablishResult.Established).entry
        assertEquals(devB, entry.remoteDeviceId)
        assertEquals(2, entry.remoteSignalDeviceId)
        assertEquals(fb.identityB64, entry.remoteIdentityPublicKeyB64)
    }

    @Test
    fun twoRemoteDevices_produceIsolatedBlobs() {
        sealLocalDevice()
        val devA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        val devB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        val fa = remoteFixture(signalDeviceId = 1)
        val fb = remoteFixture(signalDeviceId = 2)
        api.directoryHandler = { listOf(recipientOf(devA, fa), recipientOf(devB, fb)) }
        api.claimHandler = { id, _ ->
            when (id) {
                devA -> claimOf(devA, fa)
                else -> claimOf(devB, fb)
            }
        }
        val e = establisher()
        runBlocking {
            e.establish(session, server, "bob", devA)
            e.establish(session, server, "bob", devB)
        }
        val a = sessionBlobFile(devA).readBytes()
        val b = sessionBlobFile(devB).readBytes()
        assertFalse(a.contentEquals(b))
        // Both reusable without further claims.
        val claimsBefore = api.claimCalls
        runBlocking {
            assertTrue((e.establish(session, server, "bob", devA) as SessionEstablishResult.Established).reused)
            assertTrue((e.establish(session, server, "bob", devB) as SessionEstablishResult.Established).reused)
        }
        assertEquals(claimsBefore, api.claimCalls)
    }

    // ---- discovery errors ----

    @Test
    fun emptyDirectory_reportsNoDevices_withoutClaim() {
        sealLocalDevice()
        api.directoryHandler = { emptyList() }
        val result = runBlocking { establisher().establish(session, server, "bob", "any-device") }
        assertEquals(SessionEstablishResult.NoDevices, result)
        assertEquals(0, api.claimCalls)
    }

    @Test
    fun unknownDeviceId_reportsDeviceNotFound() {
        sealLocalDevice()
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf("other-device", f)) }
        val result = runBlocking { establisher().establish(session, server, "bob", "wanted-device") }
        assertEquals(SessionEstablishResult.DeviceNotFound("wanted-device"), result)
        assertEquals(0, api.claimCalls)
    }

    @Test
    fun directoryFailures_mapCorrectly() {        sealLocalDevice()
        api.directoryHandler = { throw EnrollException.Unauthorized() }
        assertEquals(
            SessionEstablishResult.Unauthorized,
            runBlocking { establisher().establish(session, server, "bob", "d") },
        )
        api.directoryHandler = { throw EnrollException.Forbidden() }
        assertEquals(
            SessionEstablishResult.NotFriends,
            runBlocking { establisher().establish(session, server, "bob", "d") },
        )
        api.directoryHandler = { throw EnrollException.NotFound() }
        assertEquals(
            SessionEstablishResult.TargetNotFound,
            runBlocking { establisher().establish(session, server, "bob", "d") },
        )
        api.directoryHandler = { throw EnrollException.Transport() }
        assertEquals(
            SessionEstablishResult.TransportRetryable,
            runBlocking { establisher().establish(session, server, "bob", "d") },
        )
    }

    @Test
    fun claimFailures_mapCorrectly() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }

        api.claimHandler = { _, _ -> throw EnrollException.NotFound() }
        assertEquals(
            SessionEstablishResult.DeviceNotActive,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
        api.claimHandler = { _, _ -> throw EnrollException.Forbidden() }
        assertEquals(
            SessionEstablishResult.NotFriends,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
        api.claimHandler = { _, _ -> throw EnrollException.Unauthorized() }
        assertEquals(
            SessionEstablishResult.Unauthorized,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
    }

    @Test
    fun malformedProtocol_convergesToTransportRetryable() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        // Malformed directory body: nothing cached, retry safe.
        api.directoryHandler = { throw EnrollException.Malformed() }
        assertEquals(
            SessionEstablishResult.TransportRetryable,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
        // Malformed claim body: may hide a consumed OTPK, but the next
        // attempt still claims fresh — nothing cached or persisted here.
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> throw EnrollException.Malformed() }
        assertEquals(
            SessionEstablishResult.TransportRetryable,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
        assertEquals(null, sessionMeta.read(deviceId))
        assertFalse(sessionBlobFile(deviceId).isFile)
    }

    @Test
    fun claimConflictTwice_reportsClaimConflict() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        api.directoryHandler = { listOf(recipientOf(deviceId, remoteFixture())) }
        api.claimHandler = { _, _ -> throw EnrollException.Conflict() }
        assertEquals(
            SessionEstablishResult.ClaimConflict,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
        // One internal retry with a fresh requestId.
        assertEquals(2, api.claimCalls)
        assertEquals(2, api.claimRequestIds.toSet().size)
    }

    @Test
    fun claimConflictOnce_thenSucceeds_withFreshRequestId() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        var first = true
        api.claimHandler = { _, _ ->
            if (first) {
                first = false
                throw EnrollException.Conflict()
            }
            claimOf(deviceId, f)
        }
        val result = runBlocking { establisher().establish(session, server, "bob", deviceId) }
        assertTrue(result is SessionEstablishResult.Established)
        assertEquals(2, api.claimRequestIds.toSet().size)
    }

    // ---- bundle validation ----

    @Test
    fun missingKyber_rejectedWithoutClaimBurn() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f, kyber = false)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f).copy(kyberPrekeyId = null, kyberPrekey = null, kyberPrekeySignature = null) }
        assertEquals(
            SessionEstablishResult.KyberUnsupported,
            runBlocking { establisher().establish(session, server, "bob", deviceId) },
        )
    }

    @Test
    fun tamperedSignature_rejectedAsInvalidBundle() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ ->
            val good = claimOf(deviceId, f)
            val badSig = SpikeCryptoMaterial.encodeBase64(
                SpikeCryptoMaterial.decodeBase64(good.signedPrekeySignature)
                    .copyOf().also { it[0] = (it[0] + 1).toByte() }
            )
            good.copy(signedPrekeySignature = badSig)
        }
        val result = runBlocking { establisher().establish(session, server, "bob", deviceId) }
        assertTrue(result is SessionEstablishResult.InvalidBundle)
        // Nothing persisted for a failed establishment.
        assertEquals(null, sessionMeta.read(deviceId))
        assertFalse(sessionBlobFile(deviceId).isFile)
    }

    @Test
    fun malformedBase64_rejectedAsInvalidBundle() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f).copy(deviceIdentityPublicKey = "!!!not-base64!!!") }
        assertTrue(
            runBlocking { establisher().establish(session, server, "bob", deviceId) }
                is SessionEstablishResult.InvalidBundle
        )
    }

    @Test
    fun failedEstablishment_nextAttemptUsesFreshClaim() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        var failFirst = true
        api.claimHandler = { _, _ ->
            if (failFirst) {
                failFirst = false
                // Burned claim: invalid bundle, establishment must fail.
                claimOf(deviceId, f).copy(signedPrekey = "!!!not-base64!!!")
            } else {
                claimOf(deviceId, f)
            }
        }
        val e = establisher()
        assertTrue(runBlocking { e.establish(session, server, "bob", deviceId) } is SessionEstablishResult.InvalidBundle)
        val retry = runBlocking { e.establish(session, server, "bob", deviceId) }
        assertTrue(retry is SessionEstablishResult.Established)
        assertFalse((retry as SessionEstablishResult.Established).reused)
        assertEquals(2, api.claimCalls)
        assertEquals(2, api.claimRequestIds.toSet().size)
    }

    // ---- durability / consistency ----

    @Test
    fun changedPin_failsClosedAsIdentityMismatch() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f) }
        val e = establisher()
        assertTrue(runBlocking { e.establish(session, server, "bob", deviceId) } is SessionEstablishResult.Established)
        // Attacker (or rotated) identity overwrites the pin out of band.
        val entry = sessionMeta.read(deviceId)!!
        sessionMeta.write(entry.copy(remoteIdentityPublicKeyB64 = remoteFixture().identityB64))
        val claimsBefore = api.claimCalls
        assertEquals(
            SessionEstablishResult.IdentityMismatch,
            runBlocking { e.establish(session, server, "bob", deviceId) },
        )
        // Fail-closed before any network: no new claim burned.
        assertEquals(claimsBefore, api.claimCalls)
    }

    @Test
    fun metadataWithoutBlob_reportsSessionUnavailable() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f) }
        val e = establisher()
        runBlocking { e.establish(session, server, "bob", deviceId) }
        assertTrue(sessionBlobFile(deviceId).delete())
        val result = runBlocking { e.establish(session, server, "bob", deviceId) }
        assertTrue(result is SessionEstablishResult.SessionUnavailable)
    }

    @Test
    fun blobWithoutMetadata_reestablishesFresh() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f) }
        val e = establisher()
        runBlocking { e.establish(session, server, "bob", deviceId) }
        // Orphan blob: metadata lost, blob kept (never silently deleted).
        FileSessionMetadataStore(context).remove(deviceId)
        assertTrue(sessionBlobFile(deviceId).isFile)
        val retry = runBlocking { e.establish(session, server, "bob", deviceId) }
        assertTrue(retry is SessionEstablishResult.Established)
        assertFalse((retry as SessionEstablishResult.Established).reused)
        assertEquals(2, api.claimCalls)
    }

    @Test
    fun swappedBlobs_failClosed() {
        sealLocalDevice()
        val devA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        val devB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        val fa = remoteFixture(signalDeviceId = 1)
        val fb = remoteFixture(signalDeviceId = 2)
        api.directoryHandler = { listOf(recipientOf(devA, fa), recipientOf(devB, fb)) }
        api.claimHandler = { id, _ -> if (id == devA) claimOf(devA, fa) else claimOf(devB, fb) }
        val e = establisher()
        runBlocking {
            e.establish(session, server, "bob", devA)
            e.establish(session, server, "bob", devB)
        }
        // Cross-device ciphertext swap: AAD-bound envelopes refuse to open
        // under the wrong handle, so reuse fails closed.
        val aBytes = sessionBlobFile(devA).readBytes()
        sessionBlobFile(devA).writeBytes(sessionBlobFile(devB).readBytes())
        sessionBlobFile(devB).writeBytes(aBytes)
        val result = runBlocking { e.establish(session, server, "bob", devA) }
        assertTrue(result is SessionEstablishResult.SessionUnavailable)
    }

    @Test
    fun noAdoptedDevice_reportsCryptoUnavailable() {
        val result = runBlocking { establisher().establish(session, server, "bob", "d") }
        assertEquals(SessionEstablishResult.CryptoUnavailable, result)
        assertEquals(0, api.directoryCalls)
    }

    @Test
    fun missingWrappingKey_reportsCryptoUnavailable() {
        sealLocalDevice()
        keys.dropKey()
        val result = runBlocking { establisher().establish(session, server, "bob", "d") }
        assertEquals(SessionEstablishResult.CryptoUnavailable, result)
        assertEquals(0, api.directoryCalls)
    }

    @Test
    fun blankTarget_rejectedWithoutNetwork() {
        sealLocalDevice()
        assertTrue(
            runBlocking { establisher().establish(session, server, "", "d") }
                is SessionEstablishResult.InvalidBundle
        )
        assertEquals(0, api.directoryCalls)
    }

    @Test
    fun concurrentEstablishment_sharesOneClaim() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ ->
            delay(200)
            claimOf(deviceId, f)
        }
        val e = establisher()
        runBlocking {
            val a = async { e.establish(session, server, "bob", deviceId) }
            val b = async { e.establish(session, server, "bob", deviceId) }
            assertTrue(a.await() is SessionEstablishResult.Established)
            assertTrue(b.await() is SessionEstablishResult.Established)
        }
        // Exactly one directory read and one claim for the shared attempt.
        assertEquals(1, api.directoryCalls)
        assertEquals(1, api.claimCalls)
    }

    @Test
    fun sessionMetadata_listsEntries() {
        sealLocalDevice()
        val deviceId = "22222222-2222-3333-4444-555555555555"
        val f = remoteFixture()
        api.directoryHandler = { listOf(recipientOf(deviceId, f)) }
        api.claimHandler = { _, _ -> claimOf(deviceId, f) }
        runBlocking { establisher().establish(session, server, "bob", deviceId) }
        val all: List<com.samvaad.android.session.SignalSessionEntry> =
            FileSessionMetadataStore(context).listAll()
        assertEquals(1, all.size)
        assertEquals(deviceId, all.single().remoteDeviceId)
    }
}
