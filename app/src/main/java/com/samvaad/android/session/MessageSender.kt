package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.CryptoRecoveryException
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.db.MessageDao
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.SubmitMessageResult
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.CancellationException

/**
 * Headless outbound message sender. Kept out of Compose by design;
 * testable without UI.
 *
 * Durable state machine per message row: `PENDING_SEAL` → `SEALED` →
 * `SENT` (terminal). The Room row is both the crash-recoverable outbox
 * attempt and, eventually, the durable history row: encrypt → insert
 * `PENDING_SEAL` (ciphertext + sealed plaintext + requestId) → seal the
 * ratchet-advanced session → mark `SEALED` → submit the exact stored
 * bytes → mark `SENT` with the server-assigned identity. A `SEALED` row
 * is never re-encrypted and its bytes/requestId never mutated; a
 * `PENDING_SEAL` row can never be submitted (its session may be
 * uncommitted) and is superseded by delete + fresh send instead.
 *
 * This class never performs recipient discovery or OTPK claims (zero on
 * the send path), never generates identities or sessions, and returns
 * plaintext-bearing results in memory only. Sends to the same remote
 * device execute sequentially under the shared [deviceLocks] holder,
 * which MUST be the same instance the inbox processor uses. No DI.
 */
class MessageSender(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val identityVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
    /**
     * Shared per-device locks. MUST be the same holder instance the
     * inbox processor uses: outbound encryption and inbound decryption
     * mutate the same durable SessionRecord and must serialize per
     * peer device. Defaults to a private holder (existing tests).
     */
    private val deviceLocks: SessionDeviceLocks = SessionDeviceLocks(),
    private val db: MessageDatabase,
    private val contentSealer: MessageContentSealer,
) {
    private fun dao(): MessageDao = db.messageDao()

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
        return deviceLocks.withDeviceLock(remoteDeviceId) {
            doSend(session, serverAddress, remoteUsername, remoteDeviceId, plaintext)
        }
    }

    /**
     * Recover this device's unfinished outbound rows. `SEALED` rows
     * resubmit byte-identically (server idempotency arbitrates);
     * `PENDING_SEAL` rows are superseded (their session may be
     * uncommitted) by delete + fresh send. Never re-encrypts a `SEALED`
     * row, never mutates stored bytes. Returns one outcome per row;
     * empty means nothing was pending. Not a boot sweep — the caller
     * decides when to invoke it.
     */
    suspend fun recoverUnsent(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
    ): List<RecoverOutcome> {
        if (remoteUsername.isBlank() || remoteDeviceId.isBlank()) return emptyList()
        return deviceLocks.withDeviceLock(remoteDeviceId) {
            val rows = try {
                dao().pendingOutbox()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return@withDeviceLock listOf(
                    RecoverOutcome.RowFailed(
                        "*",
                        SendResult.Failed(SendFailure.Rejected("message-store-failed")),
                    )
                )
            }
            rows.filter { it.recipientDeviceId == remoteDeviceId }
                .sortedBy { it.createdAt }
                .map { row ->
                    when (row.sendState) {
                        SendState.SEALED -> resubmitRow(session, serverAddress, row)
                        else -> supersedeRow(session, serverAddress, remoteUsername, remoteDeviceId, row)
                    }
                }
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
        // Bind-adopted records carry no handles: fail closed, never proceed
        // to crypto without local private material.
        val identityHandleId = adopted.identityHandleId
            ?: return SendResult.Failed(SendFailure.CryptoUnavailable)
        val localIdentity = try {
            restoreLocalIdentity(identityHandleId)
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

        val messageId = UUID.randomUUID().toString()
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
        // Seal the plaintext for the durable row before anything else is
        // persisted: cleartext must never reach the database.
        val sealedPlaintext = try {
            contentSealer.seal(messageId, plaintext)
        } catch (_: VaultException.WrappingKeyMissing) {
            return SendResult.Failed(SendFailure.CryptoUnavailable)
        } catch (_: VaultException) {
            return SendResult.Failed(SendFailure.Rejected("content-seal-failed"))
        } catch (_: IllegalArgumentException) {
            return SendResult.Failed(SendFailure.Rejected("content-seal-failed"))
        }
        // Durable attempt row first: from here on, every crash window is
        // recoverable (supersede while PENDING_SEAL, resubmit once SEALED).
        val row = MessageEntity(
            messageId = messageId,
            conversationId = "",
            sequenceNumber = 0L,
            direction = MessageDirection.OUT,
            senderDeviceId = adopted.deviceId,
            recipientDeviceId = entry.remoteDeviceId,
            envelopeType = encrypted.envelopeType,
            ciphertext = encrypted.ciphertextBytes,
            plaintextSealed = sealedPlaintext,
            sendState = SendState.PENDING_SEAL,
            acked = false,
            requestId = requestId.toString(),
            serverMessageId = null,
            serverTimestamp = "",
            createdAt = System.currentTimeMillis(),
        )
        try {
            val rowId = dao().insertIgnore(row)
            if (rowId == -1L) return SendResult.Failed(SendFailure.Rejected("message-conflict"))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return SendResult.Failed(SendFailure.Rejected("message-store-failed"))
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
        try {
            if (dao().markSealed(messageId) != 1) {
                return SendResult.Failed(SendFailure.Rejected("message-store-failed"))
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return SendResult.Failed(SendFailure.Rejected("message-store-failed"))
        }

        val envelope = MessageEnvelopeSubmit(
            senderDeviceId = adopted.deviceId,
            recipientDeviceId = entry.remoteDeviceId,
            envelopeType = encrypted.envelopeType,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(encrypted.ciphertextBytes),
        )
        val attempt = LiveAttempt(session, serverAddress, messageId, requestId, envelope, entry)
        return submitAttempt(attempt)
    }

    /** Resubmit a `SEALED` row byte-identically; never re-encrypts. */
    private suspend fun resubmitRow(
        session: AuthSession,
        serverAddress: String,
        row: MessageEntity,
    ): RecoverOutcome {
        val storedRequestId = try {
            UUID.fromString(row.requestId)
        } catch (_: IllegalArgumentException) {
            return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.Rejected("message-store-failed"))
            )
        }
        val storedCiphertext = row.ciphertext
            ?: return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.Rejected("message-store-failed"))
            )
        val entry = sessions.read(row.recipientDeviceId)
            ?: return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.SessionUnavailable("no-session"))
            )
        val envelope = MessageEnvelopeSubmit(
            senderDeviceId = row.senderDeviceId,
            recipientDeviceId = row.recipientDeviceId,
            envelopeType = row.envelopeType,
            ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(storedCiphertext),
        )
        return when (
            val result = submitAttempt(
                LiveAttempt(session, serverAddress, row.messageId, storedRequestId, envelope, entry)
            )
        ) {
            is SendResult.Sent -> RecoverOutcome.Resubmitted(row.messageId, result)
            is SendResult.Failed -> RecoverOutcome.RowFailed(row.messageId, result)
        }
    }

    /**
     * Supersede a `PENDING_SEAL` row: its session may be uncommitted, so
     * its bytes/requestId must never be submitted. Open the sealed
     * plaintext (fail closed, row kept), delete the row, then send fresh
     * through the normal path (new messageId + requestId).
     */
    private suspend fun supersedeRow(
        session: AuthSession,
        serverAddress: String,
        remoteUsername: String,
        remoteDeviceId: String,
        row: MessageEntity,
    ): RecoverOutcome {
        val sealedPlaintext = row.plaintextSealed
            ?: return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.Rejected("message-store-failed"))
            )
        val plaintext = try {
            contentSealer.open(row.messageId, sealedPlaintext)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.CryptoUnavailable)
            )
        }
        try {
            dao().deleteMessage(row.messageId)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return RecoverOutcome.RowFailed(
                row.messageId, SendResult.Failed(SendFailure.Rejected("message-store-failed"))
            )
        }
        return RecoverOutcome.Superseded(
            oldMessageId = row.messageId,
            fresh = doSend(session, serverAddress, remoteUsername, remoteDeviceId, plaintext),
        )
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
        val localMessageId: String,
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
        // Reconcile the durable row with the server-assigned identity.
        // If this write fails, the row stays SEALED and the next recovery
        // replays the identical request (server answers 200) and retries
        // the mark — so still report the server truthful outcome now.
        try {
            dao().markAccepted(
                messageId = attempt.localMessageId,
                serverMessageId = accepted.messageId,
                conversationId = accepted.conversationId,
                sequenceNumber = accepted.sequenceNumber,
                serverTimestamp = accepted.serverTimestamp,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Deliberately fall through to Sent: the server accepted, and
            // the SEALED row drives convergence on the next recovery.
        }
        return SendResult.Sent(
            entry = attempt.entry,
            messageId = accepted.messageId,
            localMessageId = attempt.localMessageId,
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
