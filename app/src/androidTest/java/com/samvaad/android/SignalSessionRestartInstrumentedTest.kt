package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.RecordEnvelopeCodec
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SignalSessionEntry
import java.io.File
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device Signal session durability: REAL libsignal natives (device
 * ABI) + REAL Keystore wrapping key + REAL vault files.
 *
 * Restart simulation in two phases, driven from the host:
 *
 * 1. `sealPhase` — establish an outbound session against locally
 *    generated remote material (no network in this slice), seal the
 *    canonical SessionRecord bytes + session metadata, persist ONLY
 *    non-secret identifiers to a phase file in the cache dir.
 * 2. Host runs `adb shell am force-stop com.samvaad.android` (and
 *    optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process: unseal, inspect (sender chain +
 *    pinned identity), restore the local identity, and prove the session
 *    still encrypts.
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 * No private material ever touches the phase file.
 */
@RunWith(AndroidJUnit4::class)
class SignalSessionRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun identityVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider())

    private fun sessionVault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider(), FileSessionMetadataStore.SUBDIR)

    private fun phaseFile(): File = File(context.cacheDir, "signal-session-restart-phase.txt")

    private val remoteDeviceId = "22222222-2222-3333-4444-555555555555"
    private val remoteUsername = "bob"
    private val remoteSignalDeviceId = 2

    @Test
    fun sealPhase() {
        phaseFile().delete()
        FileSessionMetadataStore(context).remove(remoteDeviceId)

        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        identityVault().seal(
            local.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(local.privateHandle)
        )

        // Remote bundle from a second adapter acting as the peer device.
        val peer = AndroidSignalAdapter()
        val peerIdentity = peer.generateIdentity()
        val peerSigned = peer.generateSignedPrekey(peerIdentity, 11)
        val peerKyber = peer.generateKyberPrekey(peerIdentity, 21)
        val peerOtk = peer.generateOneTimePrekey(101)
        val established = adapter.establishOutboundSession(
            localIdentity = local,
            localRegistrationId = 4242,
            remoteUsername = remoteUsername,
            remote = RemotePrekeyBundle(
                registrationId = 7001,
                signalDeviceId = remoteSignalDeviceId,
                identityKey = peerIdentity.publicKey,
                signedPrekeyId = peerSigned.prekeyId,
                signedPrekey = peerSigned.publicKey,
                signedPrekeySignature = peerSigned.signature,
                oneTimePrekeyId = peerOtk.prekeyId,
                oneTimePrekey = peerOtk.publicKey,
                kyberPrekeyId = peerKyber.prekeyId,
                kyberPrekey = peerKyber.publicKey,
                kyberPrekeySignature = peerKyber.signature,
            ),
        )
        val handle = SessionEstablisher.sessionHandleFor(remoteDeviceId)
        sessionVault().seal(handle, CryptoRecordKind.SESSION, established.sessionBytes)

        val now = System.currentTimeMillis()
        FileSessionMetadataStore(context).write(
            SignalSessionEntry(
                remoteDeviceId = remoteDeviceId,
                remoteUsername = remoteUsername,
                remoteSignalDeviceId = remoteSignalDeviceId,
                remoteRegistrationId = 7001,
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

        // Fresh process, fresh instances: only files + Keystore persist.
        val freshSessionVault = sessionVault()
        val freshIdentityVault = identityVault()
        val freshAdapter = AndroidSignalAdapter()
        val handle = SessionEstablisher.sessionHandleFor(deviceId)

        val blob = freshSessionVault.unseal(handle, CryptoRecordKind.SESSION)
        val info = freshAdapter.inspectSession(blob)
        assertArrayEquals(expectedIdentity, info.remoteIdentityBytes)
        assertEquals(7001, info.remoteRegistrationId)

        // Metadata survived alongside the blob.
        val entry = FileSessionMetadataStore(context).read(deviceId)!!
        assertEquals(username, entry.remoteUsername)
        assertEquals(remoteSignalDeviceId, entry.remoteSignalDeviceId)
        assertArrayEquals(
            expectedIdentity,
            Base64.getDecoder().decode(entry.remoteIdentityPublicKeyB64),
        )

        // The recovered session still encrypts with the restored identity.
        val localHandle = SpikeCryptoMaterial.SealedHandle(
            java.util.UUID.fromString(localHandleId), CryptoRecordKind.IDENTITY
        )
        val localBytes = freshIdentityVault.unseal(localHandle, CryptoRecordKind.IDENTITY)
        val local = when (val r = freshAdapter.restoreRecord(localHandle, localBytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> r.value
            else -> throw AssertionError("unexpected restore kind")
        }
        val wire = freshAdapter.probeEncrypt(
            local, 4242, blob, expectedIdentity,
            username, remoteSignalDeviceId, "post-restart".toByteArray(),
        )
        assertTrue(wire.isNotEmpty())
    }

    @Test
    fun keystoreRoundTrip_singleProcess() {
        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        val peer = AndroidSignalAdapter()
        val peerIdentity = peer.generateIdentity()
        val peerSigned = peer.generateSignedPrekey(peerIdentity, 11)
        val peerKyber = peer.generateKyberPrekey(peerIdentity, 21)
        val established = adapter.establishOutboundSession(
            local, 4242, "carol",
            RemotePrekeyBundle(
                registrationId = 7002,
                signalDeviceId = 3,
                identityKey = peerIdentity.publicKey,
                signedPrekeyId = peerSigned.prekeyId,
                signedPrekey = peerSigned.publicKey,
                signedPrekeySignature = peerSigned.signature,
                oneTimePrekeyId = null,
                oneTimePrekey = null,
                kyberPrekeyId = peerKyber.prekeyId,
                kyberPrekey = peerKyber.publicKey,
                kyberPrekeySignature = peerKyber.signature,
            ),
        )
        val deviceId = "33333333-3333-3333-3333-333333333333"
        val handle = SessionEstablisher.sessionHandleFor(deviceId)
        sessionVault().seal(handle, CryptoRecordKind.SESSION, established.sessionBytes)

        // Fresh adapter, same Keystore: unseal + inspect.
        val fresh = AndroidSignalAdapter()
        val back = sessionVault().unseal(handle, CryptoRecordKind.SESSION)
        val info = fresh.inspectSession(back)
        assertArrayEquals(established.remoteIdentityBytes, info.remoteIdentityBytes)
    }

    @Test
    fun corruptBlob_failsClosedOnDevice() {
        val adapter = AndroidSignalAdapter()
        val local = adapter.generateIdentity()
        val peer = AndroidSignalAdapter()
        val peerIdentity = peer.generateIdentity()
        val peerSigned = peer.generateSignedPrekey(peerIdentity, 11)
        val peerKyber = peer.generateKyberPrekey(peerIdentity, 21)
        val peerOtk = peer.generateOneTimePrekey(101)
        val established = adapter.establishOutboundSession(
            local, 4242, "dave",
            RemotePrekeyBundle(
                registrationId = 7003,
                signalDeviceId = 4,
                identityKey = peerIdentity.publicKey,
                signedPrekeyId = peerSigned.prekeyId,
                signedPrekey = peerSigned.publicKey,
                signedPrekeySignature = peerSigned.signature,
                oneTimePrekeyId = peerOtk.prekeyId,
                oneTimePrekey = peerOtk.publicKey,
                kyberPrekeyId = peerKyber.prekeyId,
                kyberPrekey = peerKyber.publicKey,
                kyberPrekeySignature = peerKyber.signature,
            ),
        )
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            // Bitwise inversion is a structural kill for the protobuf
            // record (verified on host + device). Note: the record format
            // tolerates some localized mutations, so blob integrity rests
            // on vault AES-GCM, not on parse fragility — inspect is the
            // readiness + pin gate, the vault is the integrity layer.
            val inverted = established.sessionBytes.copyOf().also { out ->
                for (i in out.indices) out[i] = out[i].toInt().inv().toByte()
            }
            adapter.inspectSession(inverted)
        }
    }

    @Test
    fun noPlaintextSessionMaterial_onDisk() {
        val dir = File(File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR), "")
        if (!dir.isDirectory) return
        // Envelope structure scan: every SESSION_ file must parse as a
        // SESSION-kind envelope (opaque ciphertext, never raw records).
        dir.listFiles { f -> f.name.startsWith("SESSION_") }.orEmpty().forEach { file ->
            val parsed = RecordEnvelopeCodec.parse(file.readBytes())
            assertEquals(CryptoRecordKind.SESSION, parsed.kind)
        }
        // Metadata carries identifiers + public keys only: no 1569-byte
        // Kyber public blobs, no 32-byte private scalars are asserted
        // structurally — the file must remain small JSON.
        val meta = File(dir, "sessions.json")
        if (meta.isFile) {
            assertTrue(meta.length() < 100 * 1024)
        }
    }
}
