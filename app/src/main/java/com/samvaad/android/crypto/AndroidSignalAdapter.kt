package com.samvaad.android.crypto

import com.samvaad.android.crypto.SpikeCryptoMaterial.Identity
import com.samvaad.android.crypto.SpikeCryptoMaterial.KyberPrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.OneTimePrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.SpikeCryptoMaterial.SignedPrekey
import java.util.Arrays
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.NoSessionException
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

    /** Canonical session bytes plus the embedded remote trust anchor. */
    data class EstablishedSession(
        val sessionBytes: ByteArray,
        val remoteIdentityBytes: ByteArray,
        val remoteRegistrationId: Int,
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
