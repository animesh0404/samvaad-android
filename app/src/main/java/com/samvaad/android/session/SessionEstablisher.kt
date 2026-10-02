package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.CryptoRecoveryException
import com.samvaad.android.crypto.RemotePrekeyBundle
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Outbound-only Signal session establishment orchestrator. Kept out of
 * Compose by design; testable without UI.
 *
 * Reuse-first invariant: a valid durable session
 * (metadata + sealed blob + sender chain + pinned identity match) is
 * reused with no claim and no second `SessionBuilder.process`. Only an
 * explicit `(username, deviceId)` target is ever established — multiple
 * ACTIVE remote devices are never auto-selected.
 *
 * Claim-burn invariant: once a claim response is received, its bundle is
 * used at most once. Any failure after the claim surfaces without
 * caching the bundle, so the next attempt makes a fresh claim with a
 * fresh `requestId`. `requestId` belongs only to the current attempt and
 * is never persisted.
 *
 * The local identity always comes from the already-adopted device
 * (vault + [DeviceMetadataStore]); this class never generates one.
 * Construction is explicit; no DI framework.
 */
class SessionEstablisher(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val identityVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
) {
    private val mutex = Mutex()
    private val inFlight = mutableMapOf<String, CompletableDeferred<SessionEstablishResult>>()

    /**
     * Establish (or reuse) the durable session for exactly
     * [remoteDeviceId] of [remoteUsername]. Concurrent callers for the
     * same device share one result; different devices proceed
     * independently.
     */
    suspend fun establish(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
    ): SessionEstablishResult {
        if (remoteUsername.isBlank() || remoteDeviceId.isBlank()) {
            return SessionEstablishResult.InvalidBundle("invalid-target")
        }
        val mine: CompletableDeferred<SessionEstablishResult>
        val owner: Boolean
        mutex.withLock {
            val existing = inFlight[remoteDeviceId]
            if (existing == null) {
                mine = CompletableDeferred()
                inFlight[remoteDeviceId] = mine
                owner = true
            } else {
                mine = existing
                owner = false
            }
        }
        if (!owner) return mine.await()
        return try {
            val outcome = doEstablish(session, serverAddress, remoteUsername, remoteDeviceId)
            mine.complete(outcome)
            outcome
        } catch (t: Throwable) {
            mine.completeExceptionally(t)
            throw t
        } finally {
            mutex.withLock {
                if (inFlight[remoteDeviceId] === mine) inFlight.remove(remoteDeviceId)
            }
        }
    }

    private suspend fun doEstablish(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
    ): SessionEstablishResult {
        val adopted = localMetadata.readAdopted()
            ?: return SessionEstablishResult.CryptoUnavailable
        val localIdentity = try {
            restoreLocalIdentity(adopted.identityHandleId)
        } catch (_: VaultException.WrappingKeyMissing) {
            return SessionEstablishResult.CryptoUnavailable
        } catch (_: VaultException) {
            return SessionEstablishResult.CryptoUnavailable
        } catch (_: CryptoRecoveryException) {
            return SessionEstablishResult.CryptoUnavailable
        } catch (_: IllegalArgumentException) {
            return SessionEstablishResult.CryptoUnavailable
        }

        val existing = sessions.read(remoteDeviceId)
        if (existing != null && existing.remoteUsername == remoteUsername) {
            // Reuse path: no network, no claim, no second process.
            val pinned = try {
                SpikeCryptoMaterial.decodeBase64(existing.remoteIdentityPublicKeyB64)
            } catch (_: IllegalArgumentException) {
                return SessionEstablishResult.SessionUnavailable("session-metadata-corrupt")
            }
            val blob = try {
                sessionVault.unseal(sessionHandleFor(remoteDeviceId), CryptoRecordKind.SESSION)
            } catch (_: VaultException.WrappingKeyMissing) {
                return SessionEstablishResult.CryptoUnavailable
            } catch (_: VaultException) {
                return SessionEstablishResult.SessionUnavailable("session-blob-missing")
            }
            val info = try {
                adapter.inspectSession(blob)
            } catch (_: SessionCryptoException) {
                return SessionEstablishResult.SessionUnavailable("session-corrupt")
            }
            if (!info.remoteIdentityBytes.contentEquals(pinned)) {
                return SessionEstablishResult.IdentityMismatch
            }
            return SessionEstablishResult.Established(existing, reused = true)
        }
        // No entry, or the username changed (miss, never silent
        // migration): fresh establishment overwrites on success.

        val directory = try {
            api.listRecipientDevices(session, serverAddress, remoteUsername)
        } catch (e: EnrollException) {
            return mapDirectoryError(e)
        } catch (_: IOException) {
            return SessionEstablishResult.TransportRetryable
        }
        if (directory.isEmpty()) return SessionEstablishResult.NoDevices
        directory.firstOrNull { it.deviceId == remoteDeviceId }
            ?: return SessionEstablishResult.DeviceNotFound(remoteDeviceId)

        val claim = try {
            claimWithRetry(session, serverAddress, remoteDeviceId)
        } catch (e: EnrollException) {
            return mapClaimError(e)
        } catch (_: IOException) {
            return SessionEstablishResult.TransportRetryable
        }
        if (claim.deviceId != remoteDeviceId) {
            return SessionEstablishResult.InvalidBundle("claim-device-mismatch")
        }
        val remote = when (val mapped = toRemoteBundle(claim)) {
            is BundleMap.Ok -> mapped.bundle
            is BundleMap.Fail -> return mapped.result
        }
        val establishedVia = if (claim.oneTimePrekey == null) {
            EstablishedVia.SIGNED_FALLBACK
        } else {
            EstablishedVia.WITH_OTPK
        }
        val established = try {
            adapter.establishOutboundSession(
                localIdentity = localIdentity,
                localRegistrationId = adopted.registrationId,
                remoteUsername = remoteUsername,
                remote = remote,
            )
        } catch (e: SessionCryptoException.InvalidBundle) {
            return SessionEstablishResult.InvalidBundle("invalid-bundle")
        } catch (_: SessionCryptoException.KyberUnsupported) {
            return SessionEstablishResult.KyberUnsupported
        } catch (_: SessionCryptoException.InvalidSignature) {
            return SessionEstablishResult.InvalidBundle("invalid-signature")
        } catch (_: SessionCryptoException.UntrustedIdentity) {
            return SessionEstablishResult.IdentityMismatch
        } catch (_: SessionCryptoException.EstablishmentFailed) {
            // The claimed OTPK is burned; the next attempt claims fresh.
            return SessionEstablishResult.Rejected("establishment-failed")
        } catch (_: SessionCryptoException.SessionCorrupt) {
            return SessionEstablishResult.SessionUnavailable("session-corrupt")
        }
        // Defense: the established record must embed the claimed bundle.
        val claimedIdentity = try {
            SpikeCryptoMaterial.decodeBase64(claim.deviceIdentityPublicKey)
        } catch (_: IllegalArgumentException) {
            return SessionEstablishResult.InvalidBundle("malformed-bundle")
        }
        if (!established.remoteIdentityBytes.contentEquals(claimedIdentity) ||
            established.remoteRegistrationId != claim.registrationId
        ) {
            return SessionEstablishResult.InvalidBundle("bundle-mismatch")
        }

        val handle = sessionHandleFor(remoteDeviceId)
        try {
            sessionVault.seal(handle, CryptoRecordKind.SESSION, established.sessionBytes)
        } catch (_: VaultException.WrappingKeyMissing) {
            return SessionEstablishResult.CryptoUnavailable
        } catch (_: VaultException) {
            return SessionEstablishResult.SessionUnavailable("session-persist-failed")
        }
        val now = System.currentTimeMillis()
        val entry = SignalSessionEntry(
            remoteDeviceId = remoteDeviceId,
            remoteUsername = remoteUsername,
            remoteSignalDeviceId = claim.signalDeviceId,
            remoteRegistrationId = claim.registrationId,
            remoteIdentityPublicKeyB64 =
                SpikeCryptoMaterial.encodeBase64(established.remoteIdentityBytes),
            establishedVia = establishedVia,
            localIdentityHandleId = adopted.identityHandleId,
            createdAt = now,
            updatedAt = now,
        )
        try {
            sessions.write(entry)
        } catch (_: IOException) {
            return SessionEstablishResult.SessionUnavailable("session-metadata-failed")
        }
        return SessionEstablishResult.Established(entry, reused = false)
    }

    /** One claim, plus a single retry with a fresh `requestId` on 409. */
    private suspend fun claimWithRetry(
        session: AuthSession,
        serverAddress: String,
        remoteDeviceId: String,
    ): ClaimedDeviceBundle {
        try {
            return api.claimOneTimePrekey(session, serverAddress, remoteDeviceId, UUID.randomUUID())
        } catch (e: EnrollException.Conflict) {
            return api.claimOneTimePrekey(session, serverAddress, remoteDeviceId, UUID.randomUUID())
        }
    }

    private fun mapDirectoryError(e: EnrollException): SessionEstablishResult = when (e) {
        is EnrollException.Unauthorized -> SessionEstablishResult.Unauthorized
        is EnrollException.Forbidden -> SessionEstablishResult.NotFriends
        is EnrollException.NotFound -> SessionEstablishResult.TargetNotFound
        is EnrollException.RecoveryRequired ->
            SessionEstablishResult.Rejected("recovery-required")
        is EnrollException.BadRequest -> SessionEstablishResult.Rejected("bad-request")
        is EnrollException.Conflict -> SessionEstablishResult.Rejected("conflict")
        is EnrollException.ServerRejected -> SessionEstablishResult.Rejected("server-rejected")
        is EnrollException.Transport -> SessionEstablishResult.TransportRetryable
        // Malformed 2xx converges here: nothing was cached or persisted,
        // and any retry claims fresh — but unlike a clean transport
        // failure, a malformed claim response may hide an already-consumed
        // OTPK, which the fresh-claim rule already accounts for.
        is EnrollException.Malformed -> SessionEstablishResult.TransportRetryable
    }

    private fun mapClaimError(e: EnrollException): SessionEstablishResult =
        when (e) {
            is EnrollException.Unauthorized -> SessionEstablishResult.Unauthorized
            is EnrollException.Forbidden -> SessionEstablishResult.NotFriends
            // The device vanished or became inactive between directory
            // and claim: re-discover, never fall through to another device.
            is EnrollException.NotFound -> SessionEstablishResult.DeviceNotActive
            is EnrollException.Conflict -> SessionEstablishResult.ClaimConflict
            is EnrollException.RecoveryRequired ->
                SessionEstablishResult.Rejected("recovery-required")
            is EnrollException.BadRequest -> SessionEstablishResult.Rejected("bad-request")
            is EnrollException.ServerRejected -> SessionEstablishResult.Rejected("server-rejected")
            is EnrollException.Transport -> SessionEstablishResult.TransportRetryable
            // Same convergence as the directory path: nothing cached or
            // persisted, retries claim fresh (see above).
            is EnrollException.Malformed -> SessionEstablishResult.TransportRetryable
        }

    private sealed interface BundleMap {
        data class Ok(val bundle: RemotePrekeyBundle) : BundleMap
        data class Fail(val result: SessionEstablishResult) : BundleMap
    }

    private fun toRemoteBundle(claim: ClaimedDeviceBundle): BundleMap {
        val identity = decode(claim.deviceIdentityPublicKey)
            ?: return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        val signed = decode(claim.signedPrekey)
            ?: return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        val signedSig = decode(claim.signedPrekeySignature)
            ?: return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        if (identity.isEmpty() || signed.isEmpty() || signedSig.isEmpty()) {
            return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        }
        val kyberId = claim.kyberPrekeyId
        val kyber = claim.kyberPrekey?.let(::decode)
        val kyberSig = claim.kyberPrekeySignature?.let(::decode)
        if (kyberId == null || claim.kyberPrekey == null || claim.kyberPrekeySignature == null) {
            return BundleMap.Fail(SessionEstablishResult.KyberUnsupported)
        }
        if (kyber == null || kyberSig == null || kyber.isEmpty() || kyberSig.isEmpty()) {
            return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        }
        val otk = claim.oneTimePrekey
        val otkBytes = otk?.let { decode(it.publicKey) }
        if (otk != null && (otkBytes == null || otkBytes.isEmpty())) {
            return BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        }
        return try {
            BundleMap.Ok(
                RemotePrekeyBundle(
                    registrationId = claim.registrationId,
                    signalDeviceId = claim.signalDeviceId,
                    identityKey = identity,
                    signedPrekeyId = claim.signedPrekeyId,
                    signedPrekey = signed,
                    signedPrekeySignature = signedSig,
                    oneTimePrekeyId = otk?.prekeyId,
                    oneTimePrekey = otkBytes,
                    kyberPrekeyId = kyberId,
                    kyberPrekey = kyber,
                    kyberPrekeySignature = kyberSig,
                )
            )
        } catch (_: IllegalArgumentException) {
            BundleMap.Fail(SessionEstablishResult.InvalidBundle("malformed-bundle"))
        }
    }

    private fun decode(value: String): ByteArray? = try {
        SpikeCryptoMaterial.decodeBase64(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun restoreLocalIdentity(handleId: String): SpikeCryptoMaterial.Identity {
        val handle = SpikeCryptoMaterial.SealedHandle(
            UUID.fromString(handleId), CryptoRecordKind.IDENTITY
        )
        val bytes = identityVault.unseal(handle, CryptoRecordKind.IDENTITY)
        return when (val restored = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> restored.value
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    companion object {
        /**
         * Deterministic vault handle for a remote server device: exactly
         * one durable SessionRecord per remote `deviceId`. The UUID is a
         * stable filename key, not a secret; the envelope AAD binds it to
         * the ciphertext so cross-device swaps fail authentication.
         */
        fun sessionHandleFor(remoteDeviceId: String): SpikeCryptoMaterial.SealedHandle =
            SpikeCryptoMaterial.SealedHandle(
                UUID.nameUUIDFromBytes(
                    ("samvaad-signal-session-v1:$remoteDeviceId")
                        .toByteArray(StandardCharsets.UTF_8)
                ),
                CryptoRecordKind.SESSION,
            )
    }
}
