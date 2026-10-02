package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.CryptoRecoveryException
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.SubmitMessageResult
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Headless outbound message sender. Kept out of Compose by design;
 * testable without UI.
 *
 * Normal path: existing session reuse → encrypt → seal post-encrypt
 * session → submit. This class never performs recipient discovery or
 * OTPK claims (zero on the send path), never generates identities or
 * sessions, and never persists message content or request IDs — the
 * retry holder below is memory-only and dies with the operation.
 *
 * Critical ordering: the ratchet-advanced session is sealed BEFORE any
 * HTTP request. Seal failure means no HTTP. HTTP failure after a
 * successful seal retries with byte-identical request content while the
 * operation is alive; a new logical message always mints a fresh
 * requestId and re-encrypts from current state.
 *
 * Sends to the same remote device execute sequentially under a
 * per-device mutex (tied to this instance's lifetime); different
 * devices proceed independently. Construction is explicit; no DI.
 */
class MessageSender(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val identityVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
) {
    private val mapMutex = Mutex()
    private val sendMutexes = ConcurrentHashMap<String, Mutex>()

    /**
     * Encrypt [plaintext] for exactly [remoteDeviceId] of
     * [remoteUsername] and submit it as one single-envelope message.
     * [plaintext] stays in memory, is never logged, and its exact value
     * is not an architectural contract (tests use a fixed constant).
     */
    suspend fun send(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
        plaintext: ByteArray,
    ): SendResult {
        if (remoteUsername.isBlank() || remoteDeviceId.isBlank()) {
            return SendResult.Failed(SendFailure.Rejected("invalid-target"))
        }
        if (plaintext.isEmpty()) {
            return SendResult.Failed(SendFailure.Rejected("empty-plaintext"))
        }
        val deviceMutex = mapMutex.withLock {
            sendMutexes.getOrPut(remoteDeviceId) { Mutex() }
        }
        return deviceMutex.withLock {
            doSend(session, serverAddress, remoteUsername, remoteDeviceId, plaintext)
        }
    }

    private suspend fun doSend(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
        plaintext: ByteArray,
    ): SendResult {
        val adopted = localMetadata.readAdopted()
            ?: return SendResult.Failed(SendFailure.CryptoUnavailable)
        val localIdentity = try {
            restoreLocalIdentity(adopted.identityHandleId)
        } catch (_: VaultException) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        } catch (_: CryptoRecoveryException) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        } catch (_: IllegalArgumentException) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        }
        // Reuse only: an unavailable session is reported, never
        // established here (no discovery, no claims on the send path).
        val entry = sessions.read(remoteDeviceId)
            ?.takeIf { it.remoteUsername == remoteUsername }
            ?: return SendResult.Failed(SendFailure.SessionUnavailable("no-session"))
        val pinned = try {
            SpikeCryptoMaterial.decodeBase64(entry.remoteIdentityPublicKeyB64)
        } catch (_: IllegalArgumentException) {
            return SendResult.Failed(SendFailure.SessionUnavailable("session-metadata-corrupt"))
        }
        val sealed = try {
            sessionVault.unseal(
                SessionEstablisher.sessionHandleFor(remoteDeviceId), CryptoRecordKind.SESSION
            )
        } catch (_: VaultException.WrappingKeyMissing) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        } catch (_: VaultException) {
            return SendResult.Failed(SendFailure.SessionUnavailable("session-blob-missing"))
        }
        val ready = try {
            adapter.inspectSession(sealed)
        } catch (_: SessionCryptoException) {
            return SendResult.Failed(SendFailure.SessionUnavailable("session-corrupt"))
        }
        if (!ready.remoteIdentityBytes.contentEquals(pinned)) {
            return SendResult.Failed(SendFailure.IdentityMismatch)
        }

        val requestId = UUID.randomUUID()
        val encrypted = try {
            adapter.encryptForSubmit(
                localIdentity = localIdentity,
                localRegistrationId = adopted.registrationId,
                sessionBytes = sealed,
                pinnedRemoteIdentity = pinned,
                remoteUsername = remoteUsername,
                remoteSignalDeviceId = entry.remoteSignalDeviceId,
                plaintext = plaintext,
            )
        } catch (_: SessionCryptoException.UntrustedIdentity) {
            return SendResult.Failed(SendFailure.IdentityMismatch)
        } catch (_: SessionCryptoException.SessionCorrupt) {
            return SendResult.Failed(SendFailure.SessionUnavailable("session-corrupt"))
        } catch (_: SessionCryptoException) {
            // Disk state untouched: encrypt either failed or its advance
            // was discarded before storing — no HTTP either way.
            return SendResult.Failed(SendFailure.Rejected("encrypt-failed"))
        }
        // Seal BEFORE any HTTP: a persistence failure must never leave a
        // submitted ciphertext ahead of the durable ratchet state.
        try {
            sessionVault.seal(
                SessionEstablisher.sessionHandleFor(remoteDeviceId),
                CryptoRecordKind.SESSION,
                encrypted.postEncryptSessionBytes,
            )
        } catch (_: VaultException.WrappingKeyMissing) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        } catch (_: VaultException) {
            return SendResult.Failed(SendFailure.SessionUnavailable("session-persist-failed"))
        }

        val envelope = MessageEnvelopeSubmit(
            senderDeviceId = adopted.deviceId,
            recipientDeviceId = entry.remoteDeviceId,
            envelopeType = encrypted.envelopeType,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(encrypted.ciphertextBytes),
        )
        val attempt = LiveAttempt(session, serverAddress, requestId, envelope, entry)
        return submitAttempt(attempt)
    }

    /**
     * In-memory retry holder for one live send operation: the exact
     * requestId + envelope captured after persistence. Never re-encrypts,
     * never touches disk, never survives the operation. Must not be
     * carried across re-authentication — a fresh send is required there.
     */
    private inner class LiveAttempt(
        private val session: AuthSession,
        private val serverAddress: String,
        private val requestId: UUID,
        val envelope: MessageEnvelopeSubmit,
        val entry: SignalSessionEntry,
    ) {
        suspend fun resubmit(): SendResult = submitAttempt(this)

        suspend fun submitOnce(): SubmitMessageResult =
            api.submitMessage(session, serverAddress, requestId, listOf(envelope))
    }

    private suspend fun submitAttempt(attempt: LiveAttempt): SendResult {
        val accepted = try {
            attempt.submitOnce()
        } catch (e: EnrollException) {
            return mapSubmitError(e) { attempt.resubmit() }
        } catch (_: IOException) {
            return SendResult.Failed(SendFailure.TransportRetryable) { attempt.resubmit() }
        }
        return SendResult.Sent(
            entry = attempt.entry,
            messageId = accepted.messageId,
            conversationId = accepted.conversationId,
            sequenceNumber = accepted.sequenceNumber,
            envelopeType = attempt.envelope.envelopeType,
            createdNew = accepted.createdNew,
        )
    }

    private fun mapSubmitError(
        e: EnrollException,
        retry: (suspend () -> SendResult)? = null,
    ): SendResult = when (e) {
        is EnrollException.Unauthorized ->
            SendResult.Failed(SendFailure.Unauthorized)
        is EnrollException.Forbidden ->
            SendResult.Failed(SendFailure.Forbidden)
        is EnrollException.NotFound ->
            SendResult.Failed(SendFailure.NotFound)
        // Same requestId, different content: fail closed. A fresh
        // requestId is only ever minted for a NEW logical message with
        // NEW ciphertext — never as an automatic retry of these bytes.
        is EnrollException.Conflict ->
            SendResult.Failed(SendFailure.Conflict)
        is EnrollException.BadRequest ->
            SendResult.Failed(SendFailure.BadRequest)
        is EnrollException.RecoveryRequired ->
            SendResult.Failed(SendFailure.Rejected("recovery-required"))
        is EnrollException.ServerRejected ->
            SendResult.Failed(SendFailure.Rejected("server-rejected"))
        is EnrollException.Malformed ->
            SendResult.Failed(SendFailure.Rejected("malformed-response"))
        is EnrollException.Transport ->
            SendResult.Failed(SendFailure.TransportRetryable, retry)
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
}
