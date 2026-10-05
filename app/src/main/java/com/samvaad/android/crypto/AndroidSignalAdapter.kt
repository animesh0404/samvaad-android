package com.samvaad.android.crypto

import com.samvaad.android.crypto.SpikeCryptoMaterial.Identity
import com.samvaad.android.crypto.SpikeCryptoMaterial.KyberPrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.OneTimePrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.SpikeCryptoMaterial.SignedPrekey
import java.util.Arrays
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
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
     * Proof-of-possession for the session→device attach handshake (mirrors
     * the server `AttachProof` spec byte-for-byte):
     * `SHA-256("samvaad-attach-v1" || X25519(identityPriv,
     * serverEphemeral) || deviceUuid16 || sessionUuid16)`.
     *
     * [serverEphemeralPublicKey] is the raw 32-byte X25519 half from
     * `attach/begin`; the `0x05` DJB type prefix is applied here because
     * libsignal parses typed encodings. UUIDs serialize big-endian
     * most/least bits, matching the server's `ByteBuffer` layout.
     *
     * Fail-closed: unknown handle, malformed ephemeral, or missing
     * private material throws [CryptoRecoveryException] — callers must
     * surface device state, never retry the same proof.
     */
    fun computeAttachProof(
        identityHandle: SealedHandle,
        serverEphemeralPublicKey: ByteArray,
        deviceId: java.util.UUID,
        sessionId: java.util.UUID,
    ): ByteArray {
        requireKind(identityHandle, CryptoRecordKind.IDENTITY)
        val pair = requireIdentity(identityHandle)
        if (serverEphemeralPublicKey.size != 32) {
            throw CryptoRecoveryException("attach ephemeral key must be 32 bytes")
        }
        val ephemeral = try {
            ECPublicKey(byteArrayOf(0x05) + serverEphemeralPublicKey)
        } catch (e: InvalidKeyException) {
            throw CryptoRecoveryException("attach ephemeral key malformed", e)
        }
        val shared = pair.privateKey.calculateAgreement(ephemeral)
        return try {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            digest.update("samvaad-attach-v1".toByteArray(Charsets.UTF_8))
            digest.update(shared)
            digest.update(uuidBytes(deviceId))
            digest.update(uuidBytes(sessionId))
            digest.digest()
        } finally {
            Arrays.fill(shared, 0)
        }
    }

    private fun uuidBytes(id: java.util.UUID): ByteArray =
        java.nio.ByteBuffer.allocate(16)
            .putLong(id.mostSignificantBits)
            .putLong(id.leastSignificantBits)
            .array()

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
                // Session blobs restore through inspectSession, never here:
                // they carry no private handle and need no live key object.
                CryptoRecordKind.SESSION ->
                    throw CryptoRecoveryException("session records restore via inspectSession")
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

    /**
     * Outbound Signal session establishment (slice: session establishment).
     *
     * Builds the Kyber-mandatory libsignal [PreKeyBundle] from the
     * server-supplied [remote] bundle — verifying the signed-prekey and
     * Kyber signatures under the recipient identity FIRST (the server is
     * never trusted for this) — then runs `SessionBuilder.process` with
     * the already-adopted local identity. Nothing here generates local
     * key material: [localIdentity] must already be live in this adapter
     * (restored from the vault after process death).
     *
     * The store is strictly ephemeral and outbound-only: it carries the
     * local identity pair plus an optional seed ([existingSessionBytes]
     * for continuing, [pinnedRemoteIdentity] for TOFU). Durability is the
     * caller's job — the returned [EstablishedSession.sessionBytes] are
     * the canonical `SessionRecord.serialize()` bytes to seal. Ownership
     * transfers to the caller.
     *
     * A claimed OTPK bundle must be used at most once: callers must never
     * retry with the same [remote] after failure — make a fresh claim.
     *
     * @throws SessionCryptoException fail-closed, never partial state.
     */
    fun establishOutboundSession(
        localIdentity: SpikeCryptoMaterial.Identity,
        localRegistrationId: Int,
        remoteUsername: String,
        remote: RemotePrekeyBundle,
        existingSessionBytes: ByteArray? = null,
        pinnedRemoteIdentity: ByteArray? = null,
    ): EstablishedSession {
        require(remoteUsername.isNotBlank()) { "remote username must be present" }
        val localPair = requireIdentity(localIdentity.privateHandle)
        val address = SignalProtocolAddress(remoteUsername, remote.signalDeviceId)
        val remoteIdentity = parseRemoteIdentity(remote)
        // Server is never trusted for signature validity: verify before
        // any bundle is constructed, let alone processed.
        if (!verifySignedPrekey(remote.identityKey, remote.signedPrekey, remote.signedPrekeySignature)) {
            throw SessionCryptoException.InvalidSignature("signed-prekey")
        }
        if (remote.kyberPrekey == null || remote.kyberPrekeyId == null ||
            remote.kyberPrekeySignature == null
        ) {
            throw SessionCryptoException.KyberUnsupported()
        }
        if (!verifyKyberSignature(remote.identityKey, remote.kyberPrekey, remote.kyberPrekeySignature)) {
            throw SessionCryptoException.InvalidSignature("kyber-prekey")
        }
        val bundle = buildBundle(remote, remoteIdentity)
        val pinned: IdentityKey? = pinnedRemoteIdentity?.let {
            try {
                IdentityKey(it)
            } catch (e: Exception) {
                throw SessionCryptoException.InvalidBundle(e)
            }
        }
        val store = EphemeralOutboundStore(
            localPair, localRegistrationId, address, existingSessionBytes, pinned
        )
        try {
            try {
                SessionBuilder(store, address).process(bundle)
            } catch (e: UntrustedIdentityException) {
                throw SessionCryptoException.UntrustedIdentity(e)
            } catch (e: InvalidKeyException) {
                throw SessionCryptoException.EstablishmentFailed(e)
            }
            val record = store.sessionFor(address)
                ?: throw SessionCryptoException.EstablishmentFailed()
            if (!record.hasSenderChain()) {
                throw SessionCryptoException.EstablishmentFailed()
            }
            return EstablishedSession(
                sessionBytes = record.serialize(),
                remoteIdentityBytes = record.remoteIdentityKey.serialize(),
                remoteRegistrationId = record.remoteRegistrationId,
            )
        } finally {
            closeQuietly(bundle)
            store.closeAll()
        }
    }

    /**
     * Readiness + pin gate for a stored session blob: restores the
     * canonical [SessionRecord], requires a sender chain, and reports the
     * embedded remote identity so the caller can compare it against its
     * pinned metadata. @throws SessionCryptoException.SessionCorrupt.
     */
    fun inspectSession(sessionBytes: ByteArray): SessionInfo {
        val record = try {
            SessionRecord(sessionBytes)
        } catch (e: InvalidMessageException) {
            throw SessionCryptoException.SessionCorrupt(e)
        } catch (e: Exception) {
            throw SessionCryptoException.SessionCorrupt(e)
        }
        try {
            if (!record.hasSenderChain()) throw SessionCryptoException.SessionCorrupt()
            return SessionInfo(
                remoteIdentityBytes = record.remoteIdentityKey.serialize(),
                remoteRegistrationId = record.remoteRegistrationId,
            )
        } finally {
            closeQuietly(record)
        }
    }

    /**
     * Test-only encrypt probe: proves an established session can actually
     * encrypt via `SessionCipher`. NOT message transport — the resulting
     * bytes are asserted on and discarded. Production establishment never
     * calls this.
     */
    fun probeEncrypt(
        localIdentity: SpikeCryptoMaterial.Identity,
        localRegistrationId: Int,
        sessionBytes: ByteArray,
        pinnedRemoteIdentity: ByteArray?,
        remoteUsername: String,
        remoteSignalDeviceId: Int,
        plaintext: ByteArray,
    ): ByteArray {
        val localPair = requireIdentity(localIdentity.privateHandle)
        val address = SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)
        val pinned: IdentityKey? = pinnedRemoteIdentity?.let {
            try {
                IdentityKey(it)
            } catch (e: Exception) {
                throw SessionCryptoException.InvalidBundle(e)
            }
        }
        val store = EphemeralOutboundStore(
            localPair, localRegistrationId, address, sessionBytes, pinned
        )
        try {
            return try {
                SessionCipher(store, address).encrypt(plaintext).serialize()
            } catch (e: UntrustedIdentityException) {
                throw SessionCryptoException.UntrustedIdentity(e)
            } catch (e: NoSessionException) {
                throw SessionCryptoException.SessionCorrupt(e)
            } catch (e: Exception) {
                throw SessionCryptoException.EstablishmentFailed(e)
            }
        } finally {
            store.closeAll()
        }
    }

    /**
     * Production outbound encryption for message submission (slice:
     * message submission).
     *
     * Encrypts [plaintext] with `SessionCipher` on the sealed session,
     * translates the actual `CiphertextMessage.getType()` into the
     * Samvaad envelope type (never assumed), and returns the POST-encrypt
     * `SessionRecord.serialize()` bytes alongside the wire bytes.
     * Encryption advances the ratchet on every call, so the caller MUST
     * seal [EncryptedMessage.postEncryptSessionBytes] BEFORE submitting
     * the ciphertext — submitting first can fork the session after a
     * crash or persistence failure.
     *
     * Ownership of both returned arrays transfers to the caller.
     * @throws SessionCryptoException fail-closed, never partial state.
     */
    fun encryptForSubmit(
        localIdentity: SpikeCryptoMaterial.Identity,
        localRegistrationId: Int,
        sessionBytes: ByteArray,
        pinnedRemoteIdentity: ByteArray?,
        remoteUsername: String,
        remoteSignalDeviceId: Int,
        plaintext: ByteArray,
    ): EncryptedMessage {
        require(plaintext.isNotEmpty()) { "plaintext must be non-empty" }
        val localPair = requireIdentity(localIdentity.privateHandle)
        val address = SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)
        val pinned: IdentityKey? = pinnedRemoteIdentity?.let {
            try {
                IdentityKey(it)
            } catch (e: Exception) {
                throw SessionCryptoException.InvalidBundle(e)
            }
        }
        val store = EphemeralOutboundStore(
            localPair, localRegistrationId, address, sessionBytes, pinned
        )
        try {
            val wire = try {
                SessionCipher(store, address).encrypt(plaintext)
            } catch (e: UntrustedIdentityException) {
                throw SessionCryptoException.UntrustedIdentity(e)
            } catch (e: NoSessionException) {
                throw SessionCryptoException.SessionCorrupt(e)
            } catch (e: Exception) {
                throw SessionCryptoException.EstablishmentFailed(e)
            }
            // `storeSession` already ran inside encrypt: the map holds the
            // advanced record. Export it — this is the state the caller
            // must seal before the ciphertext leaves the device.
            val record = store.sessionFor(address)
                ?: throw SessionCryptoException.EstablishmentFailed()
            if (!record.hasSenderChain()) throw SessionCryptoException.EstablishmentFailed()
            return EncryptedMessage(
                ciphertextBytes = wire.serialize(),
                envelopeType = envelopeTypeFor(wire.type),
                postEncryptSessionBytes = record.serialize(),
            )
        } finally {
            store.closeAll()
        }
    }

    /**
     * Translate the actual libsignal wire type into the Samvaad envelope
     * type. Pure function of the observed type — callers must never assume
     * which type an unacknowledged session produces. Unknown types fail
     * closed: the message must not be submitted.
     */
    fun envelopeTypeFor(libsignalType: Int): String = when (libsignalType) {
        PREKEY_TYPE -> ENVELOPE_PREKEY_INIT
        WHISPER_TYPE -> ENVELOPE_RATCHET
        else -> throw SessionCryptoException.EstablishmentFailed()
    }

    /** Encrypted outbound message plus the ratchet-advanced session state. */
    data class EncryptedMessage(
        val ciphertextBytes: ByteArray,
        val envelopeType: String,
        val postEncryptSessionBytes: ByteArray,
    )

    companion object {
        /** libsignal `CiphertextMessage.PREKEY_TYPE` (3), read off the wire object. */
        const val PREKEY_TYPE = 3

        /** libsignal `CiphertextMessage.WHISPER_TYPE` (2), read off the wire object. */
        const val WHISPER_TYPE = 2

        /** Samvaad server `envelopeType` for prekey (first/unacknowledged) messages. */
        const val ENVELOPE_PREKEY_INIT = "PREKEY_INIT"

        /** Samvaad server `envelopeType` for acknowledged-session messages. */
        const val ENVELOPE_RATCHET = "RATCHET"
    }

    /** Canonical session bytes plus the embedded remote trust anchor. */
    data class EstablishedSession(
        val sessionBytes: ByteArray,
        val remoteIdentityBytes: ByteArray,
        val remoteRegistrationId: Int,
    )

    /**
     * Production inbound decryption for mailbox consumption (slice:
     * inbound decryption).
     *
     * Decrypts one mailbox envelope against the sealed session using the
     * caller-restored local private records ([signed], [kyber], [otpks]:
     * restored from the vault by the caller, so this method never touches
     * storage). The server [envelopeType] is the discriminant —
     * `"PREKEY_INIT"` parses as [PreKeySignalMessage], `"RATCHET"` as
     * [SignalMessage]; anything else fails closed before any crypto runs.
     * Unknown prekey IDs fail closed via [InvalidKeyIdException]; Kyber
     * base-key reuse fails closed via [ReusedBaseKeyException] against an
     * adapter-scoped record (the persisted session bytes remain the
     * duplicate backstop across restarts).
     *
     * Returns the plaintext plus the POST-decrypt `SessionRecord`
     * bytes the caller MUST seal before ACKing. A repeat of an already
     * processed ciphertext throws [SessionCryptoException.DuplicateMessage]
     * without mutating the store — the caller must ACK without
     * delivering plaintext again.
     *
     * Ownership of returned arrays transfers to the caller.
     * @throws SessionCryptoException fail-closed, never partial state.
     */
    fun decryptForInbox(
        localIdentity: SpikeCryptoMaterial.Identity,
        localRegistrationId: Int,
        signed: SignedPrekey,
        kyber: KyberPrekey,
        otpks: List<OneTimePrekey>,
        sessionBytes: ByteArray,
        pinnedRemoteIdentity: ByteArray,
        remoteUsername: String,
        remoteSignalDeviceId: Int,
        envelopeType: String,
        ciphertext: ByteArray,
    ): DecryptedMessage {
        require(remoteUsername.isNotBlank()) { "remote username must be present" }
        require(ciphertext.isNotEmpty()) { "ciphertext must be non-empty" }
        if (envelopeType != ENVELOPE_PREKEY_INIT && envelopeType != ENVELOPE_RATCHET) {
            throw SessionCryptoException.InvalidBundle()
        }
        val localPair = requireIdentity(localIdentity.privateHandle)
        val address = SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)
        val pinned = try {
            SpikeCryptoMaterial.requireCanonicalIdentityKey(pinnedRemoteIdentity)
            IdentityKey(pinnedRemoteIdentity)
        } catch (e: SessionCryptoException) {
            throw e
        } catch (e: Exception) {
            throw SessionCryptoException.InvalidBundle(e)
        }
        val signedPair = requireSignedPair(signed.privateHandle, signed.prekeyId)
        val kyberPair = requireKyberPair(kyber.privateHandle, kyber.prekeyId)
        val otpkIndex = otpks.associate { it.prekeyId to it.privateHandle }
        val store = InboundDecryptStore(
            localPair, localRegistrationId, address, pinned,
            signed.prekeyId, signedPair,
            kyber.prekeyId, kyberPair,
            otpkIndex,
            sessionBytes,
        )
        try {
            val plaintext: ByteArray = try {
                val cipher = SessionCipher(store, address)
                if (envelopeType == ENVELOPE_PREKEY_INIT) {
                    cipher.decrypt(PreKeySignalMessage(ciphertext))
                } else {
                    cipher.decrypt(SignalMessage(ciphertext))
                }
            } catch (e: SessionCryptoException) {
                throw e
            } catch (e: DuplicateMessageException) {
                throw SessionCryptoException.DuplicateMessage(e)
            } catch (e: UntrustedIdentityException) {
                throw SessionCryptoException.UntrustedIdentity(e)
            } catch (e: NoSessionException) {
                throw SessionCryptoException.SessionCorrupt(e)
            } catch (e: Exception) {
                throw SessionCryptoException.SessionCorrupt(e)
            }
            val record = store.sessionFor(address)
                ?: throw SessionCryptoException.SessionCorrupt()
            if (!record.hasSenderChain()) throw SessionCryptoException.SessionCorrupt()
            return DecryptedMessage(
                plaintext = plaintext,
                postDecryptSessionBytes = record.serialize(),
                remoteIdentityBytes = record.remoteIdentityKey.serialize(),
            )
        } finally {
            store.closeAll()
        }
    }

    /** Decrypted inbound message plus the advanced session state. */
    data class DecryptedMessage(
        val plaintext: ByteArray,
        val postDecryptSessionBytes: ByteArray,
        val remoteIdentityBytes: ByteArray,
    )

    /** Remote trust anchor reported by [inspectSession]. */
    data class SessionInfo(
        val remoteIdentityBytes: ByteArray,
        val remoteRegistrationId: Int,
    )

    private fun parseRemoteIdentity(remote: RemotePrekeyBundle): IdentityKey {
        if (remote.identityKey.isEmpty()) throw SessionCryptoException.InvalidBundle()
        return try {
            SpikeCryptoMaterial.requireCanonicalIdentityKey(remote.identityKey)
            IdentityKey(remote.identityKey)
        } catch (e: SessionCryptoException) {
            throw e
        } catch (e: Exception) {
            throw SessionCryptoException.InvalidBundle(e)
        }
    }

    /**
     * Construct the Kyber-mandatory libsignal bundle. Signatures are
     * already verified by the caller; this only parses. A null OTPK pair
     * is the signed-prekey fallback (`NULL_PRE_KEY_ID` + null public).
     * The returned bundle is natively owned — callers must close it.
     */
    private fun buildBundle(remote: RemotePrekeyBundle, identity: IdentityKey): PreKeyBundle {
        if (remote.signedPrekey.isEmpty() || remote.signedPrekeySignature.isEmpty()) {
            throw SessionCryptoException.InvalidBundle()
        }
        val kyberBytes = remote.kyberPrekey
            ?: throw SessionCryptoException.KyberUnsupported()
        val kyberId = remote.kyberPrekeyId
            ?: throw SessionCryptoException.KyberUnsupported()
        val kyberSig = remote.kyberPrekeySignature
            ?: throw SessionCryptoException.KyberUnsupported()
        if (kyberBytes.isEmpty() || kyberSig.isEmpty()) {
            throw SessionCryptoException.InvalidBundle()
        }
        try {
            val signedPub = ECPublicKey(remote.signedPrekey)
            val kyberPub = KEMPublicKey(kyberBytes)
            val otkPub: ECPublicKey? = when {
                remote.oneTimePrekey == null -> null
                remote.oneTimePrekey.isEmpty() -> throw SessionCryptoException.InvalidBundle()
                else -> ECPublicKey(remote.oneTimePrekey)
            }
            return PreKeyBundle(
                remote.registrationId,
                remote.signalDeviceId,
                remote.oneTimePrekeyId ?: PreKeyBundle.NULL_PRE_KEY_ID,
                otkPub,
                remote.signedPrekeyId,
                signedPub,
                remote.signedPrekeySignature,
                identity,
                kyberId,
                kyberPub,
                kyberSig,
            )
        } catch (e: SessionCryptoException) {
            throw e
        } catch (e: Exception) {
            throw SessionCryptoException.InvalidBundle(e)
        }
    }

    /**
     * Ephemeral outbound-only [SignalProtocolStore]. Carries the local
     * identity pair/registration id plus an optional seeded session and
     * pinned remote identity. Everything else the interface demands is a
     * minimal safe stub: libsignal's outbound `process`/`encrypt` paths
     * only ever touch the session and identity stores (verified against
     * 0.86.5), so the prekey/signed-prekey/Kyber/sender-key stores throw
     * or report absence. No durability here — `storeSession` keeps the
     * record in memory and the caller seals `serialize()` to the vault.
     */
    private inner class EphemeralOutboundStore(
        private val localPair: IdentityKeyPair,
        private val localRegistrationId: Int,
        address: SignalProtocolAddress,
        seedSession: ByteArray?,
        pinnedIdentity: IdentityKey?,
    ) : SignalProtocolStore {
        private val sessions = mutableMapOf<SignalProtocolAddress, SessionRecord>()
        private val identities = mutableMapOf<SignalProtocolAddress, IdentityKey>()

        init {
            seedSession?.let { bytes ->
                try {
                    sessions[address] = SessionRecord(bytes)
                } catch (e: InvalidMessageException) {
                    throw SessionCryptoException.SessionCorrupt(e)
                } catch (e: Exception) {
                    throw SessionCryptoException.SessionCorrupt(e)
                }
            }
            pinnedIdentity?.let { identities[address] = it }
        }

        fun sessionFor(address: SignalProtocolAddress): SessionRecord? = sessions[address]

        fun closeAll() {
            sessions.values.forEach { closeQuietly(it) }
            sessions.clear()
        }

        override fun loadSession(address: SignalProtocolAddress): SessionRecord =
            sessions.getOrPut(address) { SessionRecord() }

        override fun loadExistingSessions(
            addresses: List<SignalProtocolAddress>
        ): List<SessionRecord> = addresses.mapNotNull { sessions[it] }

        override fun getSubDeviceSessions(name: String): List<Int> =
            sessions.keys.filter { it.name == name }.map { it.deviceId }

        override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
            sessions[address] = record
        }

        override fun containsSession(address: SignalProtocolAddress): Boolean =
            sessions.containsKey(address)

        override fun deleteSession(address: SignalProtocolAddress) {
            sessions.remove(address)?.let { closeQuietly(it) }
        }

        override fun deleteAllSessions(name: String) {
            sessions.keys.filter { it.name == name }.forEach { deleteSession(it) }
        }

        override fun getIdentityKeyPair(): IdentityKeyPair = localPair

        override fun getLocalRegistrationId(): Int = localRegistrationId

        override fun saveIdentity(
            address: SignalProtocolAddress,
            identity: IdentityKey,
        ): IdentityKeyStore.IdentityChange {
            val existing = identities[address]
            return if (existing == null ||
                existing.serialize().contentEquals(identity.serialize())
            ) {
                identities[address] = identity
                IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
            } else {
                IdentityKeyStore.IdentityChange.REPLACED_EXISTING
            }
        }

        override fun isTrustedIdentity(
            address: SignalProtocolAddress,
            identity: IdentityKey,
            direction: IdentityKeyStore.Direction,
        ): Boolean {
            val existing = identities[address] ?: return true
            return existing.serialize().contentEquals(identity.serialize())
        }

        override fun getIdentity(address: SignalProtocolAddress): IdentityKey =
            identities[address] ?: throw NoSessionException("no pinned identity")

        override fun loadPreKey(preKeyId: Int): PreKeyRecord =
            throw InvalidKeyIdException("one-time prekeys unsupported outbound")

        override fun storePreKey(preKeyId: Int, record: PreKeyRecord) = Unit

        override fun containsPreKey(preKeyId: Int): Boolean = false

        override fun removePreKey(preKeyId: Int) = Unit

        override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord =
            throw InvalidKeyIdException("signed prekeys unsupported outbound")

        override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = emptyList()

        override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) = Unit

        override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = false

        override fun removeSignedPreKey(signedPreKeyId: Int) = Unit

        override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord =
            throw InvalidKeyIdException("kyber prekeys unsupported outbound")

        override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = emptyList()

        override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) = Unit

        override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = false

        override fun markKyberPreKeyUsed(
            kyberPreKeyId: Int,
            signedPreKeyId: Int,
            baseKey: ECPublicKey,
        ) = Unit

        override fun storeSenderKey(
            sender: SignalProtocolAddress,
            distributionId: java.util.UUID,
            record: SenderKeyRecord,
        ) = Unit

        override fun loadSenderKey(
            sender: SignalProtocolAddress,
            distributionId: java.util.UUID,
        ): SenderKeyRecord = throw NoSessionException("sender keys unsupported")
    }

    /**
     * Ephemeral inbound-capable [SignalProtocolStore] for one decrypt
     * call. Unlike [EphemeralOutboundStore], the prekey stores are real:
     * PREKEY decrypt natively loads the signed/OTPK/Kyber private records
     * (RATCHET decrypt cannot reach them — libsignal never passes those
     * stores on that path). OTK entries are consumed in-memory on success
     * (durable OTK inventory stays with the vault/replenishment slices;
     * repeats are independently rejected as duplicates by session state).
     * No durability here — the caller seals the exported bytes.
     */
    private inner class InboundDecryptStore(
        private val localPair: IdentityKeyPair,
        private val localRegistrationId: Int,
        address: SignalProtocolAddress,
        pinnedIdentity: IdentityKey,
        private val signedId: Int,
        private val signedPair: ECKeyPair,
        private val kyberId: Int,
        private val kyberPair: KEMKeyPair,
        private val otpkIndex: Map<Int, SealedHandle>,
        seedSession: ByteArray,
    ) : SignalProtocolStore {
        private val sessions = mutableMapOf<SignalProtocolAddress, SessionRecord>()
        private val identities = mutableMapOf<SignalProtocolAddress, IdentityKey>()
        private val otpkCache = mutableMapOf<Int, ECKeyPair>()

        init {
            try {
                sessions[address] = SessionRecord(seedSession)
            } catch (e: InvalidMessageException) {
                throw SessionCryptoException.SessionCorrupt(e)
            } catch (e: Exception) {
                throw SessionCryptoException.SessionCorrupt(e)
            }
            // Slice 8 only decrypts for sessions with a pinned identity:
            // trust-on-first-use against the pin, never silent migration.
            identities[address] = pinnedIdentity
        }

        fun sessionFor(address: SignalProtocolAddress): SessionRecord? = sessions[address]

        fun closeAll() {
            sessions.values.forEach { closeQuietly(it) }
            sessions.clear()
            otpkCache.clear()
        }

        override fun loadSession(address: SignalProtocolAddress): SessionRecord =
            sessions[address] ?: throw NoSessionException("no session for inbound decrypt")

        override fun loadExistingSessions(
            addresses: List<SignalProtocolAddress>
        ): List<SessionRecord> = addresses.mapNotNull { sessions[it] }

        override fun getSubDeviceSessions(name: String): List<Int> =
            sessions.keys.filter { it.name == name }.map { it.deviceId }

        override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
            sessions[address] = record
        }

        override fun containsSession(address: SignalProtocolAddress): Boolean =
            sessions.containsKey(address)

        override fun deleteSession(address: SignalProtocolAddress) {
            sessions.remove(address)?.let { closeQuietly(it) }
        }

        override fun deleteAllSessions(name: String) {
            sessions.keys.filter { it.name == name }.forEach { deleteSession(it) }
        }

        override fun getIdentityKeyPair(): IdentityKeyPair = localPair

        override fun getLocalRegistrationId(): Int = localRegistrationId

        override fun saveIdentity(
            address: SignalProtocolAddress,
            identity: IdentityKey,
        ): IdentityKeyStore.IdentityChange {
            val existing = identities[address]
            return if (existing == null ||
                existing.serialize().contentEquals(identity.serialize())
            ) {
                identities[address] = identity
                IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
            } else {
                // Distrusted identities never reach here (isTrustedIdentity
                // gates first); a mismatch is reported, never stored.
                IdentityKeyStore.IdentityChange.REPLACED_EXISTING
            }
        }

        override fun isTrustedIdentity(
            address: SignalProtocolAddress,
            identity: IdentityKey,
            direction: IdentityKeyStore.Direction,
        ): Boolean {
            val existing = identities[address] ?: return false
            return existing.serialize().contentEquals(identity.serialize())
        }

        override fun getIdentity(address: SignalProtocolAddress): IdentityKey =
            identities[address] ?: throw NoSessionException("no pinned identity")

        override fun loadPreKey(preKeyId: Int): PreKeyRecord {
            val cached = otpkCache[preKeyId]
            if (cached != null) return PreKeyRecord(preKeyId, cached)
            val handle = otpkIndex[preKeyId] ?: throw InvalidKeyIdException("unknown one-time prekey")
            requireKind(handle, CryptoRecordKind.ONE_TIME_PREKEY)
            otpkCache[preKeyId] = requireOtpkPair(handle)
            return PreKeyRecord(preKeyId, otpkCache.getValue(preKeyId))
        }

        override fun storePreKey(preKeyId: Int, record: PreKeyRecord) = Unit

        override fun containsPreKey(preKeyId: Int): Boolean = otpkIndex.containsKey(preKeyId)

        override fun removePreKey(preKeyId: Int) {
            otpkCache.remove(preKeyId)
        }

        override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
            if (signedPreKeyId != signedId) throw InvalidKeyIdException("unknown signed prekey")
            // Inbound DH consumes only the private half: the sender already
            // verified this signature at establishment time, so the stored
            // signature/timestamp are not reconstructed here.
            val record = SignedPreKeyRecord(
                signedId, System.currentTimeMillis(), signedPair, ByteArray(0)
            )
            return record
        }

        override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = emptyList()

        override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) = Unit

        override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = signedPreKeyId == signedId

        override fun removeSignedPreKey(signedPreKeyId: Int) = Unit

        override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
            if (kyberPreKeyId != kyberId) throw InvalidKeyIdException("unknown kyber prekey")
            // Same as above: inbound PQXDH consumes only the KEM private half.
            return KyberPreKeyRecord(
                kyberId, System.currentTimeMillis(), kyberPair, ByteArray(0)
            )
        }

        override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = emptyList()

        override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) = Unit

        override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = kyberPreKeyId == kyberId

        override fun markKyberPreKeyUsed(
            kyberPreKeyId: Int,
            signedPreKeyId: Int,
            baseKey: ECPublicKey,
        ) {
            markKyberBaseKeyUsed(kyberPreKeyId, signedPreKeyId, baseKey)
        }

        override fun storeSenderKey(
            sender: SignalProtocolAddress,
            distributionId: java.util.UUID,
            record: SenderKeyRecord,
        ) = Unit

        override fun loadSenderKey(
            sender: SignalProtocolAddress,
            distributionId: java.util.UUID,
        ): SenderKeyRecord = throw NoSessionException("sender keys unsupported")
    }

    private fun requireKind(handle: SealedHandle, kind: CryptoRecordKind) {
        require(handle.kind == kind) { "handle kind mismatch" }
    }

    private fun requireIdentity(handle: SealedHandle): IdentityKeyPair =
        (privateHandles[handle] as? StoredKey.IdentityEntry)?.pair
            ?: throw CryptoRecoveryException(
                "identity private material unavailable in this process"
            )

    private fun requireSignedPair(handle: SealedHandle, expectedId: Int): ECKeyPair {
        val entry = (privateHandles[handle] as? StoredKey.SignedEntry)
            ?: throw CryptoRecoveryException("signed-prekey material unavailable in this process")
        if (entry.id != expectedId) throw CryptoRecoveryException("signed-prekey id drift")
        return entry.pair
    }

    private fun requireKyberPair(handle: SealedHandle, expectedId: Int): KEMKeyPair {
        val entry = (privateHandles[handle] as? StoredKey.KyberEntry)
            ?: throw CryptoRecoveryException("kyber material unavailable in this process")
        if (entry.id != expectedId) throw CryptoRecoveryException("kyber-prekey id drift")
        return entry.pair
    }

    private fun requireOtpkPair(handle: SealedHandle): ECKeyPair =
        (privateHandles[handle] as? StoredKey.OtpkEntry)?.pair
            ?: throw CryptoRecoveryException("one-time-prekey material unavailable in this process")

    /**
     * Consumed Kyber base keys `(kyberId, signedPrekeyId, baseKey)` seen by
     * [InboundDecryptStore.markKyberPreKeyUsed]. Process- and
     * adapter-scoped: a repeat within one process fails fast with
     * [ReusedBaseKeyException]; across restarts the persisted session
     * bytes remain the duplicate backstop (proven: repeats throw
     * `DuplicateMessageException` before key loading matters).
     */
    private val usedKyberBaseKeys = mutableSetOf<String>()

    private fun markKyberBaseKeyUsed(kyberId: Int, signedId: Int, baseKey: ECPublicKey) {
        val marker = "$kyberId:$signedId:" + baseKey.serialize().let {
            java.util.Base64.getEncoder().encodeToString(it)
        }
        if (!usedKyberBaseKeys.add(marker)) {
            throw ReusedBaseKeyException("kyber base key reuse")
        }
    }

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
