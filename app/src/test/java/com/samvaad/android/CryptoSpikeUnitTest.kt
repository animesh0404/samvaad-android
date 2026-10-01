package com.samvaad.android

import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.SpikeCryptoMaterial
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * LOCAL-ONLY libsignal feasibility spike: host-JVM leg.
 *
 * Exercises the REAL native libsignal implementation bundled in
 * `org.signal:libsignal-client:0.86.5` (desktop Linux x86_64 `.so` on this
 * host) through [AndroidSignalAdapter]. Lengths are diagnostics only; the
 * proof is libsignal parsing + signature verification.
 *
 * Makes no network requests, writes no files, touches no UI. Test-only IDs
 * below carry no production meaning.
 */
class CryptoSpikeUnitTest {

    // Clearly test-only IDs; production allocation rules are not chosen here.
    private val testRegistrationId = 4242
    private val testSignedPrekeyId = 2201
    private val testKyberPrekeyId = 4401

    @Test
    fun spike_generatesAndVerifiesAllMaterial() {
        val adapter = AndroidSignalAdapter()

        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, testSignedPrekeyId)
        val kyber = adapter.generateKyberPrekey(identity, testKyberPrekeyId)
        val otpks = (1..5).map { adapter.generateOneTimePrekey(5000 + it) }

        // Structural diagnostics (NOT the compatibility proof).
        SpikeCryptoMaterial.requireCanonicalIdentityKey(identity.publicKey)
        assertEquals(33, signed.publicKey.size)
        assertEquals(64, signed.signature.size)
        assertEquals(1569, kyber.publicKey.size)
        assertEquals(64, kyber.signature.size)
        otpks.forEach { assertEquals(33, it.publicKey.size) }

        // Actual libsignal parse semantics.
        assertTrue(adapter.parseIdentity(identity.publicKey))
        assertTrue(adapter.parseEcPublic(signed.publicKey))
        assertTrue(adapter.parseKyberPublic(kyber.publicKey))
        otpks.forEach { assertTrue(adapter.parseEcPublic(it.publicKey)) }

        // Actual libsignal signature semantics.
        assertTrue(adapter.verifySignedPrekey(identity.publicKey, signed.publicKey, signed.signature))
        assertTrue(adapter.verifyKyberSignature(identity.publicKey, kyber.publicKey, kyber.signature))

        // Tampered signatures must fail.
        val tamperedSigned = signed.signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertTrue(!adapter.verifySignedPrekey(identity.publicKey, signed.publicKey, tamperedSigned))
        val tamperedKyber = kyber.signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertTrue(!adapter.verifyKyberSignature(identity.publicKey, kyber.publicKey, tamperedKyber))

        // Garbage must not parse.
        assertTrue(!adapter.parseIdentity(ByteArray(33) { 0x07 }))
        assertTrue(!adapter.parseEcPublic(byteArrayOf(0x01, 0x02)))
        assertTrue(!adapter.parseKyberPublic(byteArrayOf(0x01, 0x02)))
    }

    @Test
    fun spike_standardBase64RoundTripAndEnrollmentShape() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, testSignedPrekeyId)
        val kyber = adapter.generateKyberPrekey(identity, testKyberPrekeyId)

        // Standard Base64 round-trip reproduces exact bytes (server contract).
        assertArrayEquals(
            identity.publicKey,
            SpikeCryptoMaterial.decodeBase64(SpikeCryptoMaterial.encodeBase64(identity.publicKey)),
        )
        assertArrayEquals(
            signed.signature,
            SpikeCryptoMaterial.decodeBase64(SpikeCryptoMaterial.encodeBase64(signed.signature)),
        )
        assertArrayEquals(
            kyber.publicKey,
            SpikeCryptoMaterial.decodeBase64(SpikeCryptoMaterial.encodeBase64(kyber.publicKey)),
        )
        // Standard alphabet: no URL-safe '-'/'_' in encoded key blobs.
        val encoded = SpikeCryptoMaterial.encodeBase64(kyber.publicKey)
        assertTrue(encoded.none { it == '-' || it == '_' })

        // In-memory enrollment shape only — never sent (no HTTP here).
        val shape = SpikeCryptoMaterial.toEnrollmentShape(
            testRegistrationId, identity, signed, kyber
        )
        assertEquals("ANDROID", shape.clientPlatform)
        assertArrayEquals(
            identity.publicKey,
            SpikeCryptoMaterial.decodeBase64(shape.deviceIdentityPublicKey),
        )
        assertArrayEquals(
            signed.publicKey,
            SpikeCryptoMaterial.decodeBase64(shape.signedPrekey),
        )
        assertArrayEquals(
            kyber.publicKey,
            SpikeCryptoMaterial.decodeBase64(shape.kyberPrekey),
        )
    }
}
