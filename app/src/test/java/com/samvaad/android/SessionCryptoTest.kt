package com.samvaad.android

import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.state.SessionRecord

/**
 * Outbound session-establishment crypto tests through the REAL native
 * libsignal 0.86.5 (host JVM leg; Keystore/vault durability is covered by
 * instrumented tests). No network, no files, no UI.
 *
 * Each test builds the remote bundle from a separate [AndroidSignalAdapter]
 * instance acting as the "remote device", so signatures and key parsing
 * are genuinely exercised — nothing here fakes a session.
 */
class SessionCryptoTest {

    private data class RemoteSide(
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

    private fun freshRemote(otkId: Int = 101): RemoteSide {
        val remote = AndroidSignalAdapter()
        val identity = remote.generateIdentity()
        val signed = remote.generateSignedPrekey(identity, 11)
        val kyber = remote.generateKyberPrekey(identity, 21)
        val otk = remote.generateOneTimePrekey(otkId)
        return RemoteSide(
            identity = identity.publicKey,
            signedId = signed.prekeyId,
            signed = signed.publicKey,
            signedSig = signed.signature,
            kyberId = kyber.prekeyId,
            kyber = kyber.publicKey,
            kyberSig = kyber.signature,
            otkId = otk.prekeyId,
            otk = otk.publicKey,
        )
    }

    private fun bundleOf(
        side: RemoteSide,
        withOtk: Boolean = true,
        registrationId: Int = 7001,
        signalDeviceId: Int = 2,
    ) = RemotePrekeyBundle(
        registrationId = registrationId,
        signalDeviceId = signalDeviceId,
        identityKey = side.identity,
        signedPrekeyId = side.signedId,
        signedPrekey = side.signed,
        signedPrekeySignature = side.signedSig,
        oneTimePrekeyId = if (withOtk) side.otkId else null,
        oneTimePrekey = if (withOtk) side.otk else null,
        kyberPrekeyId = side.kyberId,
        kyberPrekey = side.kyber,
        kyberPrekeySignature = side.kyberSig,
    )

    private fun localAdapter(): Pair<AndroidSignalAdapter, com.samvaad.android.crypto.SpikeCryptoMaterial.Identity> {
        val adapter = AndroidSignalAdapter()
        return adapter to adapter.generateIdentity()
    }

    @Test
    fun establish_withOtk_producesReadySession() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val established = adapter.establishOutboundSession(
            local, 4242, "bob", bundleOf(side)
        )
        assertTrue(established.sessionBytes.isNotEmpty())
        assertArrayEquals(side.identity, established.remoteIdentityBytes)
        assertEquals(7001, established.remoteRegistrationId)
        // Readiness gate: the sealed bytes restore with a sender chain.
        val info = adapter.inspectSession(established.sessionBytes)
        assertArrayEquals(established.remoteIdentityBytes, info.remoteIdentityBytes)
        assertEquals(7001, info.remoteRegistrationId)
    }

    @Test
    fun establish_fallbackWithoutOtk_producesReadySession() {
        val (adapter, local) = localAdapter()
        val established = adapter.establishOutboundSession(
            local, 4242, "bob", bundleOf(freshRemote(), withOtk = false)
        )
        val info = adapter.inspectSession(established.sessionBytes)
        assertArrayEquals(established.remoteIdentityBytes, info.remoteIdentityBytes)
    }

    @Test
    fun establish_missingKyber_rejectedWithoutDowngrade() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val bundle = bundleOf(side).copy(
            kyberPrekeyId = null, kyberPrekey = null, kyberPrekeySignature = null
        )
        assertThrows(SessionCryptoException.KyberUnsupported::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun establish_partialKyber_rejected() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val bundle = bundleOf(side).copy(kyberPrekeySignature = null)
        // copy() bypasses nothing: null signature with non-null id/bytes is
        // caught by the adapter's mandatory-triple check.
        assertThrows(SessionCryptoException::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun establish_garbageIdentity_rejected() {
        val (adapter, local) = localAdapter()
        val bundle = bundleOf(freshRemote()).copy(identityKey = ByteArray(33) { 0x07 })
        assertThrows(SessionCryptoException.InvalidBundle::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun establish_tamperedSignedSignature_rejected() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val bad = side.signedSig.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val bundle = bundleOf(side).copy(signedPrekeySignature = bad)
        assertThrows(SessionCryptoException.InvalidSignature::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun establish_tamperedKyberSignature_rejected() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val bad = side.kyberSig.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val bundle = bundleOf(side).copy(kyberPrekeySignature = bad)
        assertThrows(SessionCryptoException.InvalidSignature::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun establish_garbageOtk_rejected() {
        val (adapter, local) = localAdapter()
        val bundle = bundleOf(freshRemote()).copy(oneTimePrekey = ByteArray(16) { 0x01 })
        assertThrows(SessionCryptoException.InvalidBundle::class.java) {
            adapter.establishOutboundSession(local, 4242, "bob", bundle)
        }
    }

    @Test
    fun inspect_corruptBytes_rejected() {
        val (adapter, _) = localAdapter()
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            adapter.inspectSession(ByteArray(32) { 0x01 })
        }
        // Bitwise inversion is a structural kill for a real record.
        val (adapter2, local2) = localAdapter()
        val established = adapter2.establishOutboundSession(
            local2, 4242, "bob", bundleOf(freshRemote())
        )
        val inverted = established.sessionBytes.copyOf().also { out ->
            for (i in out.indices) out[i] = out[i].toInt().inv().toByte()
        }
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            adapter2.inspectSession(inverted)
        }
    }

    @Test
    fun inspect_emptySessionWithoutSenderChain_rejected() {
        val (adapter, _) = localAdapter()
        // A structurally valid but unestablished record must not pass.
        val empty = SessionRecord().serialize()
        assertThrows(SessionCryptoException.SessionCorrupt::class.java) {
            adapter.inspectSession(empty)
        }
        assertFalse(SessionRecord(empty).hasSenderChain())
    }

    @Test
    fun tofu_firstIdentityAccepted_sameAccepted_changedRejected() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val bundle = bundleOf(side)
        val first = adapter.establishOutboundSession(local, 4242, "bob", bundle)
        // Same session bytes + same pin: accepted (continuation).
        val again = adapter.establishOutboundSession(
            local, 4242, "bob", bundle,
            existingSessionBytes = first.sessionBytes,
            pinnedRemoteIdentity = first.remoteIdentityBytes,
        )
        adapter.inspectSession(again.sessionBytes)
        // Changed pin over the same seed: rejected, never merged.
        val other = freshRemote()
        assertThrows(SessionCryptoException.UntrustedIdentity::class.java) {
            adapter.establishOutboundSession(
                local, 4242, "bob", bundle,
                existingSessionBytes = first.sessionBytes,
                pinnedRemoteIdentity = other.identity,
            )
        }
    }

    @Test
    fun probeEncrypt_provesSessionUsable() {
        val (adapter, local) = localAdapter()
        val side = freshRemote()
        val established = adapter.establishOutboundSession(
            local, 4242, "bob", bundleOf(side)
        )
        val plaintext = "hello-signal".toByteArray(Charsets.UTF_8)
        val wire = adapter.probeEncrypt(
            local, 4242, established.sessionBytes, established.remoteIdentityBytes,
            "bob", 2, plaintext,
        )
        assertTrue(wire.isNotEmpty())
        assertFalse(wire.contentEquals(plaintext))
        // Fallback sessions encrypt too.
        val fallback = adapter.establishOutboundSession(
            local, 4242, "carol", bundleOf(freshRemote(), withOtk = false),
        )
        val wire2 = adapter.probeEncrypt(
            local, 4242, fallback.sessionBytes, fallback.remoteIdentityBytes,
            "carol", 2, plaintext,
        )
        assertTrue(wire2.isNotEmpty())
    }

    @Test
    fun probeEncrypt_distrustedIdentity_rejected() {
        val (adapter, local) = localAdapter()
        val established = adapter.establishOutboundSession(
            local, 4242, "bob", bundleOf(freshRemote())
        )
        assertThrows(SessionCryptoException.UntrustedIdentity::class.java) {
            adapter.probeEncrypt(
                local, 4242, established.sessionBytes, freshRemote().identity,
                "bob", 2, "x".toByteArray(),
            )
        }
    }

    @Test
    fun sessions_forTwoRemotes_areIndependent() {
        val (adapter, local) = localAdapter()
        val a = adapter.establishOutboundSession(local, 4242, "bob", bundleOf(freshRemote()))
        val b = adapter.establishOutboundSession(local, 4242, "carol", bundleOf(freshRemote()))
        assertFalse(a.sessionBytes.contentEquals(b.sessionBytes))
        assertEquals(7001, SessionRecord(a.sessionBytes).remoteRegistrationId)
        adapter.inspectSession(a.sessionBytes)
        adapter.inspectSession(b.sessionBytes)
    }
}
