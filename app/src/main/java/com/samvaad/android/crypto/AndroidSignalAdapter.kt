package com.samvaad.android.crypto

import com.samvaad.android.crypto.SpikeCryptoMaterial.Identity
import com.samvaad.android.crypto.SpikeCryptoMaterial.KyberPrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.OneTimePrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.SpikeCryptoMaterial.SignedPrekey
import java.util.Arrays
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

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
 * Responsibilities end at libsignal objects: generation, public-byte
 * extraction, signature verification, typed record export/import, and
 * native-handle lifecycle. Durability (encryption, files, Keystore) lives
 * in [AndroidCryptoVault], which only ever sees opaque record bytes.
 *
 * Private objects live in the in-memory [privateHandles] map keyed by
 * handle; entries carry the id/timestamp/signature needed to rebuild the
 * canonical record wrappers on export. The map is bounded by construction
 * (this slice generates a fixed small set); [forget] releases entries and
 * closes native handles where the libsignal type supports it.
 */
class AndroidSignalAdapter {
    private sealed interface StoredKey {
        data class IdentityEntry(val pair: IdentityKeyPair) : StoredKey
        data class SignedEntry(
            val id: Int,
            val timestamp: Long,
            val pair: ECKeyPair,
            val signature: ByteArray,
        ) : StoredKey
        data class OtpkEntry(val id: Int, val pair: ECKeyPair) : StoredKey
        data class KyberEntry(
            val id: Int,
            val timestamp: Long,
            val pair: KEMKeyPair,
            val signature: ByteArray,
        ) : StoredKey
    }

    private val privateHandles = mutableMapOf<SealedHandle, StoredKey>()

    fun generateIdentity(): Identity {
        val pair = IdentityKeyPair.generate()
        val handle = SealedHandle(CryptoRecordKind.IDENTITY)
        privateHandles[handle] = StoredKey.IdentityEntry(pair)
        return Identity(
            publicKey = pair.publicKey.serialize(),
            privateHandle = handle,
        )
    }

    fun generateSignedPrekey(identity: Identity, prekeyId: Int): SignedPrekey {
        requireKind(identity.privateHandle, CryptoRecordKind.IDENTITY)
        val identityPair = requireIdentity(identity.privateHandle)
        val signed = ECKeyPair.generate()
        val signature =
            identityPair.privateKey.calculateSignature(signed.publicKey.serialize())
        val timestamp = System.currentTimeMillis()
        val handle = SealedHandle(CryptoRecordKind.SIGNED_PREKEY)
        privateHandles[handle] = StoredKey.SignedEntry(
            prekeyId, timestamp, signed, signature.clone()
        )
        return SignedPrekey(
            prekeyId = prekeyId,
            publicKey = signed.publicKey.serialize(),
            signature = signature,
            privateHandle = handle,
        )
    }

    fun generateKyberPrekey(identity: Identity, prekeyId: Int): KyberPrekey {
        requireKind(identity.privateHandle, CryptoRecordKind.IDENTITY)
        val identityPair = requireIdentity(identity.privateHandle)
        val pair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val signature =
            identityPair.privateKey.calculateSignature(pair.publicKey.serialize())
        val timestamp = System.currentTimeMillis()
        val handle = SealedHandle(CryptoRecordKind.KYBER_PREKEY)
        privateHandles[handle] = StoredKey.KyberEntry(
            prekeyId, timestamp, pair, signature.clone()
        )
        return KyberPrekey(
            prekeyId = prekeyId,
            publicKey = pair.publicKey.serialize(),
            signature = signature,
            privateHandle = handle,
        )
    }

    fun generateOneTimePrekey(prekeyId: Int): OneTimePrekey {
        val pair = ECKeyPair.generate()
        val handle = SealedHandle(CryptoRecordKind.ONE_TIME_PREKEY)
        privateHandles[handle] = StoredKey.OtpkEntry(prekeyId, pair)
        return OneTimePrekey(
            prekeyId = prekeyId,
            publicKey = pair.publicKey.serialize(),
            privateHandle = handle,
        )
    }

    /**
     * Export the canonical libsignal record blob for [handle] — the exact
     * bytes the vault encrypts. Ownership of the returned array transfers
     * to the caller (the vault zeroes it after encryption).
     *
     * Uses only the record-serialization paths that exist in libsignal
     * 0.86.5: `IdentityKeyPair.serialize()`, `SignedPreKeyRecord`,
     * `KyberPreKeyRecord`, `PreKeyRecord`. `ECKeyPair`/`KEMKeyPair` are
     * never serialized directly (those APIs do not exist).
     */
    fun exportRecord(handle: SealedHandle): ByteArray {
        val entry = privateHandles[handle]
            ?: throw CryptoRecoveryException("private material unavailable in this process")
        return when (entry) {
            is StoredKey.IdentityEntry -> entry.pair.serialize()
            is StoredKey.SignedEntry -> {
                val record = SignedPreKeyRecord(
                    entry.id, entry.timestamp, entry.pair, entry.signature
                )
                try {
                    record.serialize()
                } finally {
                    closeQuietly(record)
                }
            }
            is StoredKey.OtpkEntry -> {
                val record = PreKeyRecord(entry.id, entry.pair)
                try {
                    record.serialize()
                } finally {
                    closeQuietly(record)
                }
            }
            is StoredKey.KyberEntry -> {
                val record = KyberPreKeyRecord(
                    entry.id, entry.timestamp, entry.pair, entry.signature
                )
                try {
                    record.serialize()
                } finally {
                    closeQuietly(record)
                }
            }
        }
    }

    /**
     * Reconstruct live libsignal objects from vault-recovered [recordBytes]
     * and re-associate them with [handle] (same UUID, so vault keys stay
     * stable across restarts). Returns the corresponding public material.
     *
     * Deserialization failure throws [CryptoRecoveryException] — fail
     * closed, never regenerate.
     */
    fun restoreRecord(handle: SealedHandle, recordBytes: ByteArray): RestoredPublic {
        try {
            return when (handle.kind) {
                CryptoRecordKind.IDENTITY -> {
                    val pair = IdentityKeyPair(recordBytes)
                    privateHandles[handle] = StoredKey.IdentityEntry(pair)
                    RestoredPublic.Identity(
                        Identity(pair.publicKey.serialize(), handle)
                    )
                }
                CryptoRecordKind.SIGNED_PREKEY -> {
                    val record = SignedPreKeyRecord(recordBytes)
                    try {
                        val pair = record.keyPair
                        val entry = StoredKey.SignedEntry(
                            record.id, record.timestamp, pair,
                            record.signature.clone(),
                        )
                        privateHandles[handle] = entry
                        RestoredPublic.Signed(
                            SignedPrekey(entry.id, pair.publicKey.serialize(), entry.signature, handle)
                        )
                    } finally {
                        closeQuietly(record)
                    }
                }
                CryptoRecordKind.ONE_TIME_PREKEY -> {
                    val record = PreKeyRecord(recordBytes)
                    try {
                        val pair = record.keyPair
                        val entry = StoredKey.OtpkEntry(record.id, pair)
                        privateHandles[handle] = entry
                        RestoredPublic.OneTime(
                            OneTimePrekey(entry.id, pair.publicKey.serialize(), handle)
                        )
                    } finally {
                        closeQuietly(record)
                    }
                }
                CryptoRecordKind.KYBER_PREKEY -> {
                    val record = KyberPreKeyRecord(recordBytes)
                    try {
                        val pair = record.keyPair
                        val entry = StoredKey.KyberEntry(
                            record.id, record.timestamp, pair,
                            record.signature.clone(),
                        )
                        privateHandles[handle] = entry
                        RestoredPublic.Kyber(
                            KyberPrekey(entry.id, pair.publicKey.serialize(), entry.signature, handle)
                        )
                    } finally {
                        closeQuietly(record)
                    }
                }
            }
        } catch (e: CryptoRecoveryException) {
            throw e
        } catch (e: Exception) {
            throw CryptoRecoveryException("stored record failed libsignal reconstruction", e)
        } finally {
            Arrays.fill(recordBytes, 0)
        }
    }

    /** Release one entry's native resources and forget the handle. */
    fun forget(handle: SealedHandle) {
        val removed = privateHandles.remove(handle) ?: return
        when (removed) {
            is StoredKey.IdentityEntry -> closeQuietly(removed.pair)
            is StoredKey.SignedEntry -> {
                closeQuietly(removed.pair.privateKey)
                Arrays.fill(removed.signature, 0)
            }
            is StoredKey.OtpkEntry -> closeQuietly(removed.pair.privateKey)
            is StoredKey.KyberEntry -> {
                closeQuietly(removed.pair)
                Arrays.fill(removed.signature, 0)
            }
        }
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

    /** Public material reconstituted by [restoreRecord], by record kind. */
    sealed interface RestoredPublic {
        data class Identity(val value: SpikeCryptoMaterial.Identity) : RestoredPublic
        data class Signed(val value: SignedPrekey) : RestoredPublic
        data class OneTime(val value: OneTimePrekey) : RestoredPublic
        data class Kyber(val value: KyberPrekey) : RestoredPublic
    }

    private fun requireKind(handle: SealedHandle, kind: CryptoRecordKind) {
        require(handle.kind == kind) { "handle kind mismatch" }
    }

    private fun requireIdentity(handle: SealedHandle): IdentityKeyPair =
        (privateHandles[handle] as? StoredKey.IdentityEntry)?.pair
            ?: throw CryptoRecoveryException(
                "identity private material unavailable in this process"
            )

    private fun closeQuietly(value: Any?) {
        if (value is AutoCloseable) {
            try {
                value.close()
            } catch (_: Exception) {
                // Best-effort native release; GC cleaners are the backstop.
            }
        }
    }
}
