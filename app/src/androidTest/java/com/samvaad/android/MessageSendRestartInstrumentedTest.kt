package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SignalSessionEntry
import java.io.File
import java.util.Base64
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device send continuity: REAL libsignal natives (device ABI) + REAL
 * Keystore wrapping key + REAL vault files. No network, no TLS, no UI.
 *
 * Restart simulation in two phases, driven from the host:
 *
 * 1. `sealPhase` — establish an outbound session against locally
 *    generated remote material, encrypt message #1 via the production
 *    seam, seal the POST-encrypt session, persist ONLY non-secret
 *    identifiers to a phase file in the cache dir.
 * 2. Host runs `adb shell am force-stop com.samvaad.android` (and
 *    optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process: unseal, inspect, restore the local
 *    identity, encrypt message #2 from the advanced ratchet state, and
 *    prove continuity (both PREKEY_INIT, ciphertexts differ, pin intact).
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 * No private material, plaintext, or ciphertext ever touches the phase
 * file.
 */
@RunWith(AndroidJUnit4::class)
class MessageSendRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun identityVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider())

    private fun sessionVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider(), FileSessionMetadataStore.SUBDIR)

    private fun phaseFile(): File = File(context.cacheDir, "message-send-restart-phase.txt")

    private val remoteDeviceId = "22222222-2222-3333-4444-555555555555"
    private val remoteUsername = "bob"
    private val remoteSignalDeviceId = 2
    private val plaintext = "samvaad-slice7-test-message".toByteArray(Charsets.UTF_8)

    private data class RemoteMaterial(
        val registrationId: Int,
        val identity: ByteArray,
        val signedId: Int,
        val signed: ByteArray,
        val signedSig: ByteArray,
        val kyberId: Int,
        val kyber: ByteArray,
        val kyberSig: ByteArray,
        val otkId: Int,
        val otk: ByteArray,
    )

    private fun freshRemote(): RemoteMaterial {
        val peer = AndroidSignalAdapter()
        val pid = peer.generateIdentity()
        val spk = peer.generateSignedPrekey(pid, 11)
        val kyb = peer.generateKyberPrekey(pid, 21)
        val otk = peer.generateOneTimePrekey(101)
        return RemoteMaterial(
            7001, pid.publicKey,
            spk.prekeyId, spk.publicKey, spk.signature,
            kyb.prekeyId, kyb.publicKey, kyb.signature,
            otk.prekeyId, otk.publicKey,
        )
    }

    @Test
    fun sealPhase() {
        phaseFile().delete()
        FileSessionMetadataStore(context).remove(remoteDeviceId)

        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        identityVault().seal(
            local.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(local.privateHandle)
        )
        val remote = freshRemote()
        val established = adapter.establishOutboundSession(
            localIdentity = local,
            localRegistrationId = 4242,
            remoteUsername = remoteUsername,
            remote = com.samvaad.android.crypto.RemotePrekeyBundle(
                remote.registrationId, remoteSignalDeviceId, remote.identity,
                remote.signedId, remote.signed, remote.signedSig,
                remote.otkId, remote.otk,
                remote.kyberId, remote.kyber, remote.kyberSig,
            ),
        )
        // Message #1 through the production seam; seal POST-encrypt state.
        val first = adapter.encryptForSubmit(
            local, 4242, established.sessionBytes, established.remoteIdentityBytes,
            remoteUsername, remoteSignalDeviceId, plaintext,
        )
        assertEquals(AndroidSignalAdapter.ENVELOPE_PREKEY_INIT, first.envelopeType)
        val handle = SessionEstablisher.sessionHandleFor(remoteDeviceId)
        sessionVault().seal(handle, CryptoRecordKind.SESSION, first.postEncryptSessionBytes)

        val now = System.currentTimeMillis()
        FileSessionMetadataStore(context).write(
            SignalSessionEntry(
                remoteDeviceId = remoteDeviceId,
                remoteUsername = remoteUsername,
                remoteSignalDeviceId = remoteSignalDeviceId,
                remoteRegistrationId = remote.registrationId,
                remoteIdentityPublicKeyB64 =
                    Base64.getEncoder().encodeToString(established.remoteIdentityBytes),
                establishedVia = EstablishedVia.WITH_OTPK,
                localIdentityHandleId = local.privateHandle.id.toString(),
                createdAt = now,
                updatedAt = now,
            )
        )
        phaseFile().writeText(
            listOf(
                "REMOTE_DEVICE_ID:$remoteDeviceId",
                "REMOTE_USERNAME:$remoteUsername",
                "LOCAL_IDENTITY_HANDLE:${local.privateHandle.id}",
                "EXPECTED_IDENTITY_B64:" +
                    Base64.getEncoder().encodeToString(established.remoteIdentityBytes),
                "FIRST_CIPHERTEXT_B64:" +
                    Base64.getEncoder().encodeToString(first.ciphertextBytes),
            ).joinToString("\n")
        )
        assertTrue(phaseFile().isFile)
    }

    @Test
    fun recoverPhase() {
        val lines = try {
            phaseFile().readLines()
        } catch (_: Exception) {
            throw AssertionError("phase file absent: run sealPhase first")
        }
        fun value(key: String): String =
            lines.first { it.startsWith("$key:") }.substringAfter(":")
        val deviceId = value("REMOTE_DEVICE_ID")
        val username = value("REMOTE_USERNAME")
        val localHandleId = value("LOCAL_IDENTITY_HANDLE")
        val expectedIdentity = Base64.getDecoder().decode(value("EXPECTED_IDENTITY_B64"))
        val firstCiphertext = Base64.getDecoder().decode(value("FIRST_CIPHERTEXT_B64"))

        // Fresh process, fresh instances: only files + Keystore persist.
        val freshAdapter = AndroidSignalAdapter()
        val handle = SessionEstablisher.sessionHandleFor(deviceId)
        val blob = sessionVault().unseal(handle, CryptoRecordKind.SESSION)
        val info = freshAdapter.inspectSession(blob)
        assertArrayEquals(expectedIdentity, info.remoteIdentityBytes)

        val entry = FileSessionMetadataStore(context).read(deviceId)!!
        assertEquals(username, entry.remoteUsername)
        assertArrayEquals(
            expectedIdentity,
            Base64.getDecoder().decode(entry.remoteIdentityPublicKeyB64),
        )

        val localHandle = SpikeCryptoMaterial.SealedHandle(
            UUID.fromString(localHandleId), CryptoRecordKind.IDENTITY
        )
        val localBytes = identityVault().unseal(localHandle, CryptoRecordKind.IDENTITY)
        val local = when (val r = freshAdapter.restoreRecord(localHandle, localBytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> r.value
            else -> throw AssertionError("unexpected restore kind")
        }
        // Message #2 from the advanced ratchet state.
        val second = freshAdapter.encryptForSubmit(
            local, 4242, blob, expectedIdentity,
            username, remoteSignalDeviceId, plaintext,
        )
        assertEquals(AndroidSignalAdapter.ENVELOPE_PREKEY_INIT, second.envelopeType)
        assertTrue(second.ciphertextBytes.isNotEmpty())
        assertFalse(firstCiphertext.contentEquals(second.ciphertextBytes))
        // The re-sealed state stays reusable with the pin intact.
        val resealed = second.postEncryptSessionBytes
        sessionVault().seal(handle, CryptoRecordKind.SESSION, resealed)
        val again = freshAdapter.inspectSession(
            sessionVault().unseal(handle, CryptoRecordKind.SESSION)
        )
        assertArrayEquals(expectedIdentity, again.remoteIdentityBytes)
    }

    @Test
    fun keystoreEncryptContinuity_singleProcess() {
        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        identityVault().seal(
            local.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(local.privateHandle)
        )
        val remote = freshRemote()
        val established = adapter.establishOutboundSession(
            local, 4242, "carol",
            com.samvaad.android.crypto.RemotePrekeyBundle(
                7002, 3, remote.identity,
                remote.signedId, remote.signed, remote.signedSig,
                remote.otkId, remote.otk,
                remote.kyberId, remote.kyber, remote.kyberSig,
            ),
        )
        val deviceId = "33333333-3333-3333-3333-333333333333"
        val handle = SessionEstablisher.sessionHandleFor(deviceId)
        val first = adapter.encryptForSubmit(
            local, 4242, established.sessionBytes, established.remoteIdentityBytes,
            "carol", 3, plaintext,
        )
        assertEquals("PREKEY_INIT", first.envelopeType)
        sessionVault().seal(handle, CryptoRecordKind.SESSION, first.postEncryptSessionBytes)

        // Fresh adapter, same Keystore: restore identity, restore session,
        // encrypt again from the advanced state.
        val fresh = AndroidSignalAdapter()
        val restoredLocal = when (
            val r = fresh.restoreRecord(
                local.privateHandle,
                identityVault().unseal(local.privateHandle, CryptoRecordKind.IDENTITY),
            )
        ) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> r.value
            else -> throw AssertionError("unexpected restore kind")
        }
        val back = sessionVault().unseal(handle, CryptoRecordKind.SESSION)
        val second = fresh.encryptForSubmit(
            restoredLocal, 4242, back, established.remoteIdentityBytes,
            "carol", 3, plaintext,
        )
        assertEquals("PREKEY_INIT", second.envelopeType)
        assertFalse(first.ciphertextBytes.contentEquals(second.ciphertextBytes))
    }
}
