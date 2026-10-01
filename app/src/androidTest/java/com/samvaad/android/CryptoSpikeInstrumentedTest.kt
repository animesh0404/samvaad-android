package com.samvaad.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.SpikeCryptoMaterial
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * LOCAL-ONLY libsignal feasibility spike: on-device leg.
 *
 * Runs the REAL Android native libsignal implementation
 * (`org.signal:libsignal-android:0.86.5` JNI `.so` for this device's ABI)
 * through [AndroidSignalAdapter]: 1 identity, 1 signed prekey, 1 Kyber
 * triple, 5 one-time prekeys. Lengths are diagnostics; libsignal parsing +
 * verification is the proof.
 *
 * No network requests, no persistence, no UI interaction, no key-byte
 * logging — assertions compare lengths/booleans/round-trips only.
 */
@RunWith(AndroidJUnit4::class)
class CryptoSpikeInstrumentedTest {

    // Clearly test-only IDs; production allocation rules are not chosen here.
    private val testRegistrationId = 4242
    private val testSignedPrekeyId = 2201
    private val testKyberPrekeyId = 4401

    @Test
    fun spike_androidNatives_generateParseAndVerify() {
        val adapter = AndroidSignalAdapter()

        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, testSignedPrekeyId)
        val kyber = adapter.generateKyberPrekey(identity, testKyberPrekeyId)
        val otpks = (1..5).map { adapter.generateOneTimePrekey(5000 + it) }
        assertEquals(5, otpks.size)

        // Structural diagnostics (NOT the compatibility proof).
        SpikeCryptoMaterial.requireCanonicalIdentityKey(identity.publicKey)
        assertEquals(33, signed.publicKey.size)
        assertEquals(64, signed.signature.size)
        assertEquals(1569, kyber.publicKey.size)
        assertEquals(64, kyber.signature.size)
        otpks.forEach { assertEquals(33, it.publicKey.size) }

        // Actual libsignal parse semantics on this ABI's natives.
        assertTrue(adapter.parseIdentity(identity.publicKey))
        assertTrue(adapter.parseEcPublic(signed.publicKey))
        assertTrue(adapter.parseKyberPublic(kyber.publicKey))
        otpks.forEach { assertTrue(adapter.parseEcPublic(it.publicKey)) }

        // Actual libsignal signature semantics on this ABI's natives.
        assertTrue(adapter.verifySignedPrekey(identity.publicKey, signed.publicKey, signed.signature))
        assertTrue(adapter.verifyKyberSignature(identity.publicKey, kyber.publicKey, kyber.signature))

        // Standard Base64 round-trip reproduces exact bytes.
        assertArrayEquals(
            kyber.publicKey,
            SpikeCryptoMaterial.decodeBase64(SpikeCryptoMaterial.encodeBase64(kyber.publicKey)),
        )

        // In-memory enrollment shape only — never sent (no HTTP here).
        val shape = SpikeCryptoMaterial.toEnrollmentShape(
            testRegistrationId, identity, signed, kyber
        )
        assertEquals("ANDROID", shape.clientPlatform)
        assertArrayEquals(
            identity.publicKey,
            SpikeCryptoMaterial.decodeBase64(shape.deviceIdentityPublicKey),
        )
    }
}
