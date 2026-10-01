package com.samvaad.android.crypto

import com.samvaad.android.crypto.SpikeCryptoMaterial.Identity
import com.samvaad.android.crypto.SpikeCryptoMaterial.KyberPrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.OneTimePrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.SpikeCryptoMaterial.SignedPrekey
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey

/**
 * LOCAL-ONLY libsignal feasibility spike adapter.
 *
 * The ONLY production-source file allowed to import
 * `org.signal.libsignal.*`. Everything above this class deals in
 * [SpikeCryptoMaterial] opaque bytes + [SealedHandle] references.
 *
 * Compatibility reference: the JVM `LibSignalAdapter`
 * (libsignal-client 0.86.5) — same `generate()` + `serialize()` +
 * `calculateSignature over serialized subject public key` semantics.
 *
 * Private objects ([IdentityKeyPair]/[ECKeyPair]/[KEMKeyPair]) live ONLY in
 * the in-memory [privateHandles] map, keyed by handle UUID — the same
 * custody shape as the JVM adapter's in-process registry, minus any vault
 * or file backend (none exists in this spike, by design). No persistence,
 * no logging of key bytes, no network.
 */
class AndroidSignalAdapter {
    private val privateHandles = mutableMapOf<SealedHandle, Any>()

    fun generateIdentity(): Identity {
        val pair = IdentityKeyPair.generate()
        val handle = SealedHandle()
        privateHandles[handle] = pair
        return Identity(
            publicKey = pair.publicKey.serialize(),
            privateHandle = handle,
        )
    }

    fun generateSignedPrekey(identity: Identity, prekeyId: Int): SignedPrekey {
        val identityPair = requireIdentity(identity.privateHandle)
        val signed = ECKeyPair.generate()
        val signature =
            identityPair.privateKey.calculateSignature(signed.publicKey.serialize())
        val handle = SealedHandle()
        privateHandles[handle] = signed
        return SignedPrekey(
            prekeyId = prekeyId,
            publicKey = signed.publicKey.serialize(),
            signature = signature,
            privateHandle = handle,
        )
    }

    fun generateKyberPrekey(identity: Identity, prekeyId: Int): KyberPrekey {
        val identityPair = requireIdentity(identity.privateHandle)
        val pair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val signature =
            identityPair.privateKey.calculateSignature(pair.publicKey.serialize())
        val handle = SealedHandle()
        privateHandles[handle] = pair
        return KyberPrekey(
            prekeyId = prekeyId,
            publicKey = pair.publicKey.serialize(),
            signature = signature,
            privateHandle = handle,
        )
    }

    fun generateOneTimePrekey(prekeyId: Int): OneTimePrekey {
        val pair = ECKeyPair.generate()
        val handle = SealedHandle()
        privateHandles[handle] = pair
        return OneTimePrekey(
            prekeyId = prekeyId,
            publicKey = pair.publicKey.serialize(),
            privateHandle = handle,
        )
    }

    /**
     * Parse check via libsignal itself: returns true only if [identityBytes]
     * parses as an [IdentityKey]. No custom validation.
     */
    fun parseIdentity(identityBytes: ByteArray): Boolean = try {
        IdentityKey(identityBytes)
        true
    } catch (_: Exception) {
        false
    }

    /** Parse check via libsignal itself for EC public material. */
    fun parseEcPublic(bytes: ByteArray): Boolean = try {
        ECPublicKey(bytes)
        true
    } catch (_: Exception) {
        false
    }

    /** Parse check via libsignal itself for Kyber public material. */
    fun parseKyberPublic(bytes: ByteArray): Boolean = try {
        KEMPublicKey(bytes)
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Real libsignal signature verification: identity public key over the
     * serialized signed-prekey public key. Mirrors JVM
     * `verifySignedPrekey`.
     */
    fun verifySignedPrekey(
        identityBytes: ByteArray,
        signedBytes: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return try {
            if (signature.isEmpty()) return false
            val identity = IdentityKey(identityBytes)
            val signed = ECPublicKey(signedBytes)
            identity.publicKey.verifySignature(signed.serialize(), signature)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Real libsignal verification for the Kyber triple: identity public key
     * over the serialized Kyber public key. Mirrors the JVM adapter's
     * Kyber `requireSignature` path.
     */
    fun verifyKyberSignature(
        identityBytes: ByteArray,
        kyberBytes: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return try {
            if (kyberBytes.isEmpty() || signature.isEmpty()) return false
            val identity = IdentityKey(identityBytes)
            // Parsing first proves the bytes are libsignal-meaningful Kyber
            // material; verification proves the identity binding.
            val parsed = KEMPublicKey(kyberBytes)
            identity.publicKey.verifySignature(parsed.serialize(), signature)
        } catch (_: Exception) {
            false
        }
    }

    private fun requireIdentity(handle: SealedHandle): IdentityKeyPair =
        privateHandles[handle] as? IdentityKeyPair
            ?: error("identity private material unavailable in this process")
}
