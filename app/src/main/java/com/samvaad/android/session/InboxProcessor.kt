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
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.highestContiguous
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.MailboxItem
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.CancellationException
import androidx.room.withTransaction
/**
 * Headless inbound mailbox processor. Kept out of Compose by design;
 * testable without UI.
 *
 * Per entry: resolve `senderDeviceId` to the existing session entry
 * (unknown senders are skipped — no discovery, no claims, no new
 * sessions) → decrypt with real libsignal → seal the plaintext into a
 * durable Room row → seal the post-decrypt session → ACK that
 * `messageId` → mark the row ACKED → advance the server cursor through
 * the highest contiguous locally durable sequence. Plaintext is
 * returned in memory only and never persisted in clear. A repeat of an
 * already-processed ciphertext throws `DuplicateMessageException`,
 * which authorizes the ACK without delivering plaintext again — the
 * experimentally proven rule — but only once the durable row is
 * confirmed present.
 *
 * Session mutation (load → decrypt → export → seal) runs under the
 * shared [SessionDeviceLocks] holder, which MUST be the same instance
 * the outbound [MessageSender] uses: both directions mutate the same
 * durable SessionRecord. ACKs run outside the lock — they are
 * server-idempotent and touch no local session state. Entries process
 * sequentially within a batch; one entry's failure never aborts or
 * ACKs another. Construction is explicit; no DI.
 */
class InboxProcessor(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val cryptoVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
    private val deviceLocks: SessionDeviceLocks = SessionDeviceLocks(),
    private val db: MessageDatabase,
    private val contentSealer: MessageContentSealer,
) {
    /**
     * Fetch up to [limit] mailbox entries and process each to completion.
     * [limit] is 1..100 (server bound).
     */
    suspend fun receive(
        session: AuthSession,
        serverAddress: String,
        limit: Int = 20,
    ): InboxResult {
        if (limit !in 1..100) return InboxResult.Failed(InboxFailure.Rejected("invalid-limit"))
        val items = try {
            api.fetchMailbox(session, serverAddress, limit)
        } catch (e: EnrollException) {
            return when (e) {
                is EnrollException.Unauthorized -> InboxResult.Failed(InboxFailure.Unauthorized)
                is EnrollException.Transport -> InboxResult.Failed(InboxFailure.TransportRetryable)
                else -> InboxResult.Failed(InboxFailure.Rejected("fetch-rejected"))
            }
        } catch (_: IOException) {
            return InboxResult.Failed(InboxFailure.TransportRetryable)
        }
        val messages = mutableListOf<InboxMessage>()
        val acked = mutableListOf<String>()
        val unacked = mutableListOf<String>()
        val skipped = mutableListOf<SkippedEntry>()
        for (item in items) {
            when (val outcome = processOne(session, serverAddress, item)) {
                is EntryOutcome.Decrypted -> {
                    messages.add(outcome.message)
                    acked.add(item.messageId)
                }
                is EntryOutcome.DeliveredUnacked -> {
                    messages.add(outcome.message)
                    unacked.add(item.messageId)
                }
                is EntryOutcome.Duplicate -> acked.add(item.messageId)
                is EntryOutcome.Skipped -> skipped.add(SkippedEntry(item.messageId, outcome.reason))
            }
        }
        return InboxResult.Completed(messages, acked, unacked, skipped)
    }

    private sealed interface EntryOutcome {
        data class Decrypted(val message: InboxMessage) : EntryOutcome
        data class DeliveredUnacked(val message: InboxMessage) : EntryOutcome
        data object Duplicate : EntryOutcome
        data class Skipped(val reason: String) : EntryOutcome
    }

    private sealed interface GateOutcome {
        data class Valid(val messageId: UUID, val ciphertext: ByteArray) : GateOutcome
        data class Invalid(val reason: String) : GateOutcome
    }

    /** Transport-encoding gates shared by mailbox and history ingestion. */
    private fun gateItem(
        envelopeType: String,
        ciphertextBase64: String,
        messageId: String,
    ): GateOutcome {
        if (envelopeType != AndroidSignalAdapter.ENVELOPE_PREKEY_INIT &&
            envelopeType != AndroidSignalAdapter.ENVELOPE_RATCHET
        ) {
            return GateOutcome.Invalid("unsupported-envelope-type")
        }
        val ciphertext = try {
            SpikeCryptoMaterial.decodeBase64(ciphertextBase64)
        } catch (_: IllegalArgumentException) {
            return GateOutcome.Invalid("malformed-ciphertext")
        }
        if (ciphertext.isEmpty()) return GateOutcome.Invalid("malformed-ciphertext")
        return try {
            GateOutcome.Valid(UUID.fromString(messageId), ciphertext)
        } catch (_: IllegalArgumentException) {
            GateOutcome.Invalid("malformed-message-id")
        }
    }

    private suspend fun processOne(
        session: AuthSession,
        serverAddress: String,
        item: MailboxItem,
    ): EntryOutcome {
        val gated = gateItem(item.envelopeType, item.ciphertextBase64, item.messageId)
        if (gated is GateOutcome.Invalid) return EntryOutcome.Skipped(gated.reason)
        gated as GateOutcome.Valid
        val messageId = gated.messageId
        val ciphertext = gated.ciphertext
        // Unknown senders fail closed here: no decrypt, no ACK, no
        // discovery, no claims, no new sessions. Other entries proceed.
        val entry = sessions.read(item.senderDeviceId)
            ?: return EntryOutcome.Skipped("unknown-sender")
        val adopted = localMetadata.readAdopted()
            ?: return EntryOutcome.Skipped("no-local-device")

        // Shared per-device lock: same SessionRecord as outbound sends.
        // ACKs, local ACK flags, and cursor moves stay outside the lock
        // (server-idempotent, no session mutation).
        return when (val decrypted = deviceLocks.withDeviceLock(entry.remoteDeviceId) {
            decryptSealAndStore(adopted, entry, item, ciphertext)
        }) {
            is DecryptOutcome.Ok -> {
                val message = InboxMessage(
                    messageId = item.messageId,
                    conversationId = item.conversationId,
                    sequenceNumber = item.sequenceNumber,
                    senderDeviceId = item.senderDeviceId,
                    envelopeType = item.envelopeType,
                    plaintext = decrypted.plaintext,
                )
                // Plaintext is delivered exactly once here. A failed ACK
                // only redelivers into the duplicate path, which then
                // authorizes the ACK without delivering again.
                if (!ackOne(session, serverAddress, messageId)) {
                    return EntryOutcome.DeliveredUnacked(message)
                }
                if (!markAcked(item.messageId)) {
                    return EntryOutcome.DeliveredUnacked(message)
                }
                maybeAdvanceCursor(session, serverAddress, item.conversationId)
                EntryOutcome.Decrypted(message)
            }
            // Exact prior-processing proof — but only with the durable row
            // present: without it, durability is unproven and nothing
            // may be ACKed (see decryptSealAndStore).
            is DecryptOutcome.Duplicate -> {
                if (dao().byMessageId(item.messageId) == null) {
                    return EntryOutcome.Skipped("message-missing")
                }
                if (!ackOne(session, serverAddress, messageId)) {
                    return EntryOutcome.Skipped("ack-failed")
                }
                if (!markAcked(item.messageId)) {
                    return EntryOutcome.Skipped("ack-failed")
                }
                maybeAdvanceCursor(session, serverAddress, item.conversationId)
                EntryOutcome.Duplicate
            }
            is DecryptOutcome.Unavailable -> EntryOutcome.Skipped(decrypted.reason)
        }
    }

    private fun dao() = db.messageDao()

    private sealed interface DecryptOutcome {
        data class Ok(val plaintext: ByteArray) : DecryptOutcome
        data object Duplicate : DecryptOutcome
        data class Unavailable(val reason: String) : DecryptOutcome
    }

    /**
     * Ingest one Primary-exported sync item into durable state (no
     * mailbox ACK: sync carries none; the caller ACKs the sync prefix
     * separately). Shares the gate + decrypt pipeline with mailbox and
     * history ingestion, but resolves the Signal session through the
     * batch-declared Primary device ([syncSenderDeviceId]) instead of
     * the item sender: synced items keep their ORIGINAL senderDeviceId
     * (friend or Primary), for which this device holds no session.
     * Persisted rows stay verbatim-original (IN, acked, no request or
     * server-message identity); only the decryption session differs.
     * Returns the authenticated frontier on [SyncIngestResult.Stored] so
     * the caller can track pending-vs-complete without trusting it.
     */
    suspend fun ingestSyncItem(
        item: com.samvaad.android.enroll.SyncBatchItem,
        syncSenderDeviceId: String,
    ): SyncIngestResult {
        val gated = gateItem(item.envelopeType, item.ciphertextBase64, item.messageId)
        if (gated is GateOutcome.Invalid) return SyncIngestResult.Skipped(gated.reason)
        gated as GateOutcome.Valid
        val ciphertext = gated.ciphertext
        // Unknown Primary fails closed here: no decrypt, no store, no
        // session creation — exactly like unknown mailbox senders.
        val entry = sessions.read(syncSenderDeviceId)
            ?: return SyncIngestResult.Skipped("unknown-sync-sender")
        val adopted = localMetadata.readAdopted()
            ?: return SyncIngestResult.Skipped("no-local-device")
        val decrypted = deviceLocks.withDeviceLock(entry.remoteDeviceId) {
            decryptChannel(adopted, entry, item.envelopeType, ciphertext)
        }
        return when (decrypted) {
            is ChannelDecrypt.Duplicate -> SyncIngestResult.Duplicate
            is ChannelDecrypt.Unavailable -> SyncIngestResult.Skipped(decrypted.reason)
            is ChannelDecrypt.Ok -> {
                val payload = try {
                    parseSyncPayload(decrypted.plaintext)
                } catch (_: SyncPayloadMalformedException) {
                    return SyncIngestResult.Skipped("malformed-sync-payload")
                }
                // Binding: the decrypted payload must describe exactly
                // the requested wire item, or the Primary (or a faulty
                // transport) mixed conversations. Fail closed, never
                // relabel.
                if (payload.messageId != item.messageId
                    || payload.sequenceNumber != item.sequenceNumber
                    || payload.conversationId != item.conversationId
                ) {
                    return SyncIngestResult.Skipped("sync-binding-mismatch")
                }
                storeSyncRow(adopted, entry, item, payload, decrypted.postDecryptSessionBytes)
            }
        }
    }

    /**
     * Persists one validated sync payload as a verbatim-original durable
     * row: direction IN, acked (never enters mailbox ACK paths),
     * original sender/recipient/message/conversation/sequence/timestamp,
     * no request or server-message identity. Mirrors the
     * decryptSealAndStore ordering (row before session seal) so any crash
     * redelivers into clean re-decrypt or proven duplicate.
     */
    private suspend fun storeSyncRow(
        adopted: com.samvaad.android.enroll.AdoptedDevice,
        entry: com.samvaad.android.session.SignalSessionEntry,
        item: com.samvaad.android.enroll.SyncBatchItem,
        payload: SyncPayload,
        postDecryptSessionBytes: ByteArray,
    ): SyncIngestResult {
        val sealedInner = try {
            contentSealer.seal(payload.messageId, payload.plaintext)
        } catch (e: CancellationException) {
            throw e
        } catch (_: com.samvaad.android.crypto.VaultException) {
            return SyncIngestResult.Skipped("crypto-unavailable")
        } catch (_: IllegalArgumentException) {
            return SyncIngestResult.Skipped("content-seal-failed")
        }
        try {
            val existing = dao().conversation(payload.conversationId)
            dao().upsertConversation(
                com.samvaad.android.db.ConversationEntity(
                    conversationId = payload.conversationId,
                    lastSeenSequence = maxOf(
                        existing?.lastSeenSequence ?: 0L, payload.sequenceNumber
                    ),
                    cursorThrough = existing?.cursorThrough ?: 0L,
                )
            )
            val inserted = dao().insertIgnore(
                com.samvaad.android.db.MessageEntity(
                    messageId = payload.messageId,
                    conversationId = payload.conversationId,
                    sequenceNumber = payload.sequenceNumber,
                    direction = com.samvaad.android.db.MessageDirection.IN,
                    senderDeviceId = payload.senderDeviceId,
                    recipientDeviceId = payload.recipientDeviceId,
                    envelopeType = item.envelopeType,
                    ciphertext = item.ciphertextBase64.let {
                        com.samvaad.android.crypto.SpikeCryptoMaterial.decodeBase64(it)
                    },
                    plaintextSealed = sealedInner,
                    sendState = null,
                    acked = true,
                    requestId = null,
                    serverMessageId = null,
                    serverTimestamp = payload.serverTimestamp,
                    createdAt = System.currentTimeMillis(),
                )
            )
            if (inserted == -1L && dao().byMessageId(payload.messageId) == null) {
                return SyncIngestResult.Skipped("message-missing")
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return SyncIngestResult.Skipped("message-store-failed")
        }
        try {
            sessionVault.seal(
                SessionEstablisher.sessionHandleFor(entry.remoteDeviceId),
                com.samvaad.android.crypto.CryptoRecordKind.SESSION,
                postDecryptSessionBytes,
            )
        } catch (_: com.samvaad.android.crypto.VaultException.WrappingKeyMissing) {
            return SyncIngestResult.Skipped("crypto-unavailable")
        } catch (_: com.samvaad.android.crypto.VaultException) {
            return SyncIngestResult.Skipped("session-persist-failed")
        }
        return SyncIngestResult.Stored(frontier = payload.frontier)
    }

    /**
     * Sync ingest outcome. [Stored] carries the batch's authenticated
     * frontier so the caller can compare it against durable contiguity.
     * [Duplicate] means the row already exists (redelivery absorbed);
     * the frontier is not re-surfaced — it was reported when first
     * stored, and re-reporting it here would let a stale batch move a
     * newer frontier backwards through a max() the caller must own.
     */
    sealed interface SyncIngestResult {
        data class Stored(val frontier: Long) : SyncIngestResult
        data object Duplicate : SyncIngestResult
        data class Skipped(val reason: String) : SyncIngestResult
    }

    /**
     * Shared Signal decrypt pipeline: identity restore, session unseal
     * + pin gate, decrypt, post-decrypt identity defense. Extracted
     * from [decryptSealAndStore] so mailbox, history, and sync ingest
     * decrypt identically; only session source (mailbox sender vs sync
     * Primary) and the persisted row shape differ per caller. No
     * behavior change for existing callers.
     */
    private sealed interface ChannelDecrypt {
        data class Ok(val plaintext: ByteArray, val postDecryptSessionBytes: ByteArray) :
            ChannelDecrypt
        data object Duplicate : ChannelDecrypt
        data class Unavailable(val reason: String) : ChannelDecrypt
    }

    /**
     * Ingest one server-history item into durable state (no mailbox ACK:
     * history carries none). Shares the gate + decrypt-seal-store core
     * with mailbox processing; returns whether the message is now
     * durable (freshly stored or already present). Cursor advancement
     * stays with the caller, which decides it from contiguity.
     */
    suspend fun ingestHistoryItem(history: com.samvaad.android.enroll.HistoryItem): HistoryIngestResult {
        // Same wire shape as MailboxItem by server design; the source
        // differs (durable envelopes vs undelivered queue), so the type
        // stays explicit and only the fields cross over.
        val item = MailboxItem(
            messageId = history.messageId,
            conversationId = history.conversationId,
            sequenceNumber = history.sequenceNumber,
            senderUserId = history.senderUserId,
            senderDeviceId = history.senderDeviceId,
            envelopeType = history.envelopeType,
            ciphertextBase64 = history.ciphertextBase64,
            serverTimestamp = history.serverTimestamp,
        )
        val gated = gateItem(item.envelopeType, item.ciphertextBase64, item.messageId)
        if (gated is GateOutcome.Invalid) return HistoryIngestResult.Skipped(gated.reason)
        gated as GateOutcome.Valid
        val entry = sessions.read(item.senderDeviceId)
            ?: return HistoryIngestResult.Skipped("unknown-sender")
        val adopted = localMetadata.readAdopted()
            ?: return HistoryIngestResult.Skipped("no-local-device")
        return when (
            val outcome = deviceLocks.withDeviceLock(entry.remoteDeviceId) {
                decryptSealAndStore(adopted, entry, item, gated.ciphertext)
            }
        ) {
            is DecryptOutcome.Ok -> HistoryIngestResult.Stored
            is DecryptOutcome.Duplicate ->
                if (dao().byMessageId(item.messageId) == null) {
                    HistoryIngestResult.Skipped("message-missing")
                } else {
                    HistoryIngestResult.Duplicate
                }
            is DecryptOutcome.Unavailable -> HistoryIngestResult.Skipped(outcome.reason)
        }
    }

    /**
     * Decrypt, durably store, and seal under the caller's device lock.
     * Plaintext is returned only alongside a Room row AND a sealed
     * post-decrypt session; every other outcome carries its fixed skip
     * reason. Ordering is load-bearing: the row lands before the session
     * seal, so any crash redelivers into either a clean re-decrypt (disk
     * still pre-decrypt) or a proven duplicate (disk advanced) — never
     * into an ambiguous state.
     */
    /**
     * Shared decrypt half of [decryptSealAndStore]: restores local
     * identity material, unseals and pin-gates the session, decrypts,
     * and re-checks the post-decrypt identity. Callers own sealing,
     * persistence, and session re-sealing from the returned bytes.
     */
    private suspend fun decryptChannel(
        adopted: com.samvaad.android.enroll.AdoptedDevice,
        entry: com.samvaad.android.session.SignalSessionEntry,
        envelopeType: String,
        ciphertext: ByteArray,
    ): ChannelDecrypt {
        val pinned = try {
            SpikeCryptoMaterial.decodeBase64(entry.remoteIdentityPublicKeyB64)
        } catch (_: IllegalArgumentException) {
            return ChannelDecrypt.Unavailable("session-metadata-corrupt")
        }
        val localIdentity = try {
            // Bind-adopted records carry no handles: fail closed, never
            // decrypt without local private material.
            val identityHandleId = adopted.identityHandleId
                ?: return ChannelDecrypt.Unavailable("crypto-unavailable")
            restoreLocal(identityHandleId, CryptoRecordKind.IDENTITY)
        } catch (_: VaultException) {
            return ChannelDecrypt.Unavailable("crypto-unavailable")
        } catch (_: CryptoRecoveryException) {
            return ChannelDecrypt.Unavailable("crypto-unavailable")
        } catch (_: IllegalArgumentException) {
            return ChannelDecrypt.Unavailable("crypto-unavailable")
        }
        // Eagerly restore the adopted private records; the OTK index is
        // derived from the records themselves, so no ID ordering is
        // assumed and the metadata schema is untouched. Absent handles
        // (bind-adopted) fail closed here.
        val signedHandleId = adopted.signedHandleId
            ?: return ChannelDecrypt.Unavailable("crypto-unavailable")
        val signed = restoreSigned(signedHandleId)
            ?: return ChannelDecrypt.Unavailable("crypto-unavailable")
        val kyberHandleId = adopted.kyberHandleId
            ?: return ChannelDecrypt.Unavailable("crypto-unavailable")
        val kyber = restoreKyber(kyberHandleId)
            ?: return ChannelDecrypt.Unavailable("crypto-unavailable")
        val otpks = adopted.otpkHandleIds.mapNotNull { restoreOtpk(it) }
        val sealed = try {
            sessionVault.unseal(
                SessionEstablisher.sessionHandleFor(entry.remoteDeviceId), CryptoRecordKind.SESSION
            )
        } catch (_: VaultException.WrappingKeyMissing) {
            return ChannelDecrypt.Unavailable("crypto-unavailable")
        } catch (_: VaultException) {
            return ChannelDecrypt.Unavailable("session-blob-missing")
        }
        // Readiness + pin gate on the CURRENT bytes before decrypting.
        try {
            val ready = adapter.inspectSession(sealed)
            if (!ready.remoteIdentityBytes.contentEquals(pinned)) {
                return ChannelDecrypt.Unavailable("identity-mismatch")
            }
        } catch (_: SessionCryptoException) {
            return ChannelDecrypt.Unavailable("session-corrupt")
        }
        val decrypted = try {
            adapter.decryptForInbox(
                localIdentity = localIdentity,
                localRegistrationId = adopted.registrationId,
                signed = signed,
                kyber = kyber,
                otpks = otpks,
                sessionBytes = sealed,
                pinnedRemoteIdentity = pinned,
                remoteUsername = entry.remoteUsername,
                remoteSignalDeviceId = entry.remoteSignalDeviceId,
                envelopeType = envelopeType,
                ciphertext = ciphertext,
            )
        } catch (_: SessionCryptoException.DuplicateMessage) {
            return ChannelDecrypt.Duplicate
        } catch (_: SessionCryptoException.UntrustedIdentity) {
            return ChannelDecrypt.Unavailable("identity-mismatch")
        } catch (_: SessionCryptoException) {
            return ChannelDecrypt.Unavailable("decrypt-failed")
        }
        // Defense: the decrypted record must still pin the same identity.
        if (!decrypted.remoteIdentityBytes.contentEquals(pinned)) {
            return ChannelDecrypt.Unavailable("identity-mismatch")
        }
        return ChannelDecrypt.Ok(decrypted.plaintext, decrypted.postDecryptSessionBytes)
    }

    private suspend fun decryptSealAndStore(
        adopted: com.samvaad.android.enroll.AdoptedDevice,
        entry: SignalSessionEntry,
        item: MailboxItem,
        ciphertext: ByteArray,
    ): DecryptOutcome {
        // Shared decrypt pipeline (see decryptChannel): identical
        // identity restore, pin gates, and decrypt semantics as before
        // this extraction; only row construction below is mailbox-shaped.
        val channel = decryptChannel(adopted, entry, item.envelopeType, ciphertext)
        val decrypted = when (channel) {
            is ChannelDecrypt.Duplicate -> return DecryptOutcome.Duplicate
            is ChannelDecrypt.Unavailable -> return DecryptOutcome.Unavailable(channel.reason)
            is ChannelDecrypt.Ok -> channel
        }
        val plaintext = decrypted.plaintext
        // Seal the plaintext for the durable row before anything else is
        // persisted: cleartext must never reach the database.
        val sealedPlaintext = try {
            contentSealer.seal(item.messageId, plaintext)
        } catch (e: CancellationException) {
            throw e
        } catch (_: VaultException) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        } catch (_: IllegalArgumentException) {
            return DecryptOutcome.Unavailable("content-seal-failed")
        }
        // Durable message row (+ conversation observation). Two
        // sequential idempotent writes instead of one transaction: a
        // crash between them leaves either nothing (redelivery decrypts
        // cleanly) or a conversation row without its message (heals on
        // the next message's upsert; contiguity is always recomputed
        // from actual rows, never from these markers). Either way the
        // next redelivery converges via insert-ignore absorption or the
        // duplicate path — never into an ambiguous state.
        try {
            val existing = dao().conversation(item.conversationId)
            dao().upsertConversation(
                ConversationEntity(
                    conversationId = item.conversationId,
                    lastSeenSequence = maxOf(
                        existing?.lastSeenSequence ?: 0L, item.sequenceNumber
                    ),
                    cursorThrough = existing?.cursorThrough ?: 0L,
                )
            )
            dao().insertIgnore(
                MessageEntity(
                    messageId = item.messageId,
                    conversationId = item.conversationId,
                    sequenceNumber = item.sequenceNumber,
                    direction = MessageDirection.IN,
                    senderDeviceId = item.senderDeviceId,
                    recipientDeviceId = adopted.deviceId,
                    envelopeType = item.envelopeType,
                    ciphertext = ciphertext,
                    plaintextSealed = sealedPlaintext,
                    sendState = null,
                    acked = false,
                    requestId = null,
                    serverMessageId = null,
                    serverTimestamp = item.serverTimestamp,
                    createdAt = System.currentTimeMillis(),
                )
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return DecryptOutcome.Unavailable("message-store-failed")
        }
        try {
            sessionVault.seal(
                SessionEstablisher.sessionHandleFor(entry.remoteDeviceId),
                CryptoRecordKind.SESSION,
                decrypted.postDecryptSessionBytes,
            )
        } catch (_: VaultException.WrappingKeyMissing) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        } catch (_: VaultException) {
            // Disk stays at the pre-decrypt state: no ACK, the entry
            // redelivers and decrypts cleanly again later (the existing
            // row is absorbed by insert-ignore on the way back).
            return DecryptOutcome.Unavailable("session-persist-failed")
        }
        return DecryptOutcome.Ok(decrypted.plaintext)
    }

    /** Best-effort local ACK flag; false leaves the row for later retry. */
    private suspend fun markAcked(messageId: String): Boolean = try {
        dao().markAcked(messageId)
        true
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        false
    }

    /**
     * Advance the server cursor through the highest contiguous locally
     * durable sequence — never through a gap, never merely because a
     * page was fetched. Best-effort: on conflict, converge the local
     * cache to the server value; on transport failure the cursor simply
     * lags for a later attempt. Never rolls back message state.
     *
     * Internal (not private) so the launch-time reconciliation sweep —
     * same module — can advance cursors after history ingestion without
     * duplicating this policy.
     */
    internal suspend fun maybeAdvanceCursor(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
    ) {
        val contiguous = try {
            highestContiguous(dao().sequencesFor(conversationId))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return
        }
        val cached = try {
            dao().conversation(conversationId)?.cursorThrough ?: 0L
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return
        }
        if (contiguous <= cached) return
        try {
            api.advanceSyncCursor(session, serverAddress, conversationId, contiguous)
            dao().setCursor(conversationId, contiguous)
        } catch (e: CancellationException) {
            throw e
        } catch (_: EnrollException.Conflict) {
            // Someone (or an earlier attempt) moved it: converge the
            // cache to the authoritative server value instead of forcing.
            try {
                val server = api.getSyncCursor(session, serverAddress, conversationId)
                dao().setCursor(conversationId, server.throughSequence)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Leave the cache; a later attempt retries.
            }
        } catch (_: Exception) {
            // Cursor lags; message state is untouched. A later receive
            // or reconciliation retries the advancement.
        }
    }

    /** Best-effort single ACK; false on any failure (entry redelivers). */
    private suspend fun ackOne(
        session: AuthSession,
        serverAddress: String,
        messageId: UUID,
    ): Boolean = try {
        api.ackMailbox(session, serverAddress, listOf(messageId))
        true
    } catch (_: EnrollException) {
        false
    } catch (_: IOException) {
        false
    }

    private fun restoreLocal(
        handleId: String,
        kind: CryptoRecordKind,
    ): SpikeCryptoMaterial.Identity {
        val handle = SpikeCryptoMaterial.SealedHandle(UUID.fromString(handleId), kind)
        val bytes = cryptoVault.unseal(handle, kind)
        return when (val restored = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> restored.value
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    private fun restoreSigned(handleId: String): SpikeCryptoMaterial.SignedPrekey? = try {
        val handle = SpikeCryptoMaterial.SealedHandle(
            UUID.fromString(handleId), CryptoRecordKind.SIGNED_PREKEY
        )
        when (val restored = adapter.restoreRecord(
            handle, cryptoVault.unseal(handle, CryptoRecordKind.SIGNED_PREKEY)
        )) {
            is AndroidSignalAdapter.RestoredPublic.Signed -> restored.value
            else -> null
        }
    } catch (_: VaultException) {
        null
    } catch (_: CryptoRecoveryException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun restoreKyber(handleId: String): SpikeCryptoMaterial.KyberPrekey? = try {
        val handle = SpikeCryptoMaterial.SealedHandle(
            UUID.fromString(handleId), CryptoRecordKind.KYBER_PREKEY
        )
        when (val restored = adapter.restoreRecord(
            handle, cryptoVault.unseal(handle, CryptoRecordKind.KYBER_PREKEY)
        )) {
            is AndroidSignalAdapter.RestoredPublic.Kyber -> restored.value
            else -> null
        }
    } catch (_: VaultException) {
        null
    } catch (_: CryptoRecoveryException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun restoreOtpk(handleId: String): SpikeCryptoMaterial.OneTimePrekey? = try {
        val handle = SpikeCryptoMaterial.SealedHandle(
            UUID.fromString(handleId), CryptoRecordKind.ONE_TIME_PREKEY
        )
        when (val restored = adapter.restoreRecord(
            handle, cryptoVault.unseal(handle, CryptoRecordKind.ONE_TIME_PREKEY)
        )) {
            is AndroidSignalAdapter.RestoredPublic.OneTime -> restored.value
            else -> null
        }
    } catch (_: VaultException) {
        null
    } catch (_: CryptoRecoveryException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }
}
