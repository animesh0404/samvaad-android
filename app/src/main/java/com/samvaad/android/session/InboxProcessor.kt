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
import com.samvaad.android.enroll.MailboxItem
import java.io.IOException
import java.util.UUID

/**
 * Headless inbound mailbox processor. Kept out of Compose by design;
 * testable without UI.
 *
 * Per entry: resolve `senderDeviceId` to the existing session entry
 * (unknown senders are skipped — no discovery, no claims, no new
 * sessions) → decrypt with real libsignal → seal the post-decrypt
 * session → ACK that `messageId`. Plaintext is returned in memory only
 * and never persisted. A repeat of an already-processed ciphertext
 * throws `DuplicateMessageException`, which authorizes the ACK without
 * delivering plaintext again — the experimentally proven rule.
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

    private suspend fun processOne(
        session: AuthSession,
        serverAddress: String,
        item: MailboxItem,
    ): EntryOutcome {
        if (item.envelopeType != AndroidSignalAdapter.ENVELOPE_PREKEY_INIT &&
            item.envelopeType != AndroidSignalAdapter.ENVELOPE_RATCHET
        ) {
            return EntryOutcome.Skipped("unsupported-envelope-type")
        }
        val ciphertext = try {
            SpikeCryptoMaterial.decodeBase64(item.ciphertextBase64)
        } catch (_: IllegalArgumentException) {
            return EntryOutcome.Skipped("malformed-ciphertext")
        }
        if (ciphertext.isEmpty()) return EntryOutcome.Skipped("malformed-ciphertext")
        val messageId = try {
            UUID.fromString(item.messageId)
        } catch (_: IllegalArgumentException) {
            return EntryOutcome.Skipped("malformed-message-id")
        }
        // Unknown senders fail closed here: no decrypt, no ACK, no
        // discovery, no claims, no new sessions. Other entries proceed.
        val entry = sessions.read(item.senderDeviceId)
            ?: return EntryOutcome.Skipped("unknown-sender")
        val adopted = localMetadata.readAdopted()
            ?: return EntryOutcome.Skipped("no-local-device")

        // Shared per-device lock: same SessionRecord as outbound sends.
        // ACKs stay outside the lock (server-idempotent, no local state).
        return when (val decrypted = deviceLocks.withDeviceLock(entry.remoteDeviceId) {
            decryptAndSeal(adopted, entry, item, ciphertext)
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
                return if (ackOne(session, serverAddress, messageId)) {
                    EntryOutcome.Decrypted(message)
                } else {
                    EntryOutcome.DeliveredUnacked(message)
                }
            }
            // Exact prior-processing proof: ACK without delivering again.
            // No session write happened, so there is nothing to persist.
            // A failed ACK only redelivers into the same duplicate path.
            is DecryptOutcome.Duplicate -> {
                if (!ackOne(session, serverAddress, messageId)) {
                    return EntryOutcome.Skipped("ack-failed")
                }
                EntryOutcome.Duplicate
            }
            is DecryptOutcome.Unavailable -> EntryOutcome.Skipped(decrypted.reason)
        }
    }

    private sealed interface DecryptOutcome {
        data class Ok(val plaintext: ByteArray) : DecryptOutcome
        data object Duplicate : DecryptOutcome
        data class Unavailable(val reason: String) : DecryptOutcome
    }

    /**
     * Decrypt + seal under the caller's device lock. Plaintext is
     * returned only alongside a successfully sealed post-decrypt
     * session; every other outcome carries its fixed skip reason.
     */
    private fun decryptAndSeal(
        adopted: com.samvaad.android.enroll.AdoptedDevice,
        entry: SignalSessionEntry,
        item: MailboxItem,
        ciphertext: ByteArray,
    ): DecryptOutcome {
        val pinned = try {
            SpikeCryptoMaterial.decodeBase64(entry.remoteIdentityPublicKeyB64)
        } catch (_: IllegalArgumentException) {
            return DecryptOutcome.Unavailable("session-metadata-corrupt")
        }
        val localIdentity = try {
            restoreLocal(adopted.identityHandleId, CryptoRecordKind.IDENTITY)
        } catch (_: VaultException) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        } catch (_: CryptoRecoveryException) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        } catch (_: IllegalArgumentException) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        }
        // Eagerly restore the adopted private records; the OTK index is
        // derived from the records themselves, so no ID ordering is
        // assumed and the metadata schema is untouched.
        val signed = restoreSigned(adopted.signedHandleId)
            ?: return DecryptOutcome.Unavailable("crypto-unavailable")
        val kyber = restoreKyber(adopted.kyberHandleId)
            ?: return DecryptOutcome.Unavailable("crypto-unavailable")
        val otpks = adopted.otpkHandleIds.mapNotNull { restoreOtpk(it) }
        val sealed = try {
            sessionVault.unseal(
                SessionEstablisher.sessionHandleFor(entry.remoteDeviceId), CryptoRecordKind.SESSION
            )
        } catch (_: VaultException.WrappingKeyMissing) {
            return DecryptOutcome.Unavailable("crypto-unavailable")
        } catch (_: VaultException) {
            return DecryptOutcome.Unavailable("session-blob-missing")
        }
        // Readiness + pin gate on the CURRENT bytes before decrypting.
        try {
            val ready = adapter.inspectSession(sealed)
            if (!ready.remoteIdentityBytes.contentEquals(pinned)) {
                return DecryptOutcome.Unavailable("identity-mismatch")
            }
        } catch (_: SessionCryptoException) {
            return DecryptOutcome.Unavailable("session-corrupt")
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
                envelopeType = item.envelopeType,
                ciphertext = ciphertext,
            )
        } catch (_: SessionCryptoException.DuplicateMessage) {
            return DecryptOutcome.Duplicate
        } catch (_: SessionCryptoException.UntrustedIdentity) {
            return DecryptOutcome.Unavailable("identity-mismatch")
        } catch (_: SessionCryptoException) {
            return DecryptOutcome.Unavailable("decrypt-failed")
        }
        // Defense: the decrypted record must still pin the same identity.
        if (!decrypted.remoteIdentityBytes.contentEquals(pinned)) {
            return DecryptOutcome.Unavailable("identity-mismatch")
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
            // redelivers and decrypts cleanly again later.
            return DecryptOutcome.Unavailable("session-persist-failed")
        }
        return DecryptOutcome.Ok(decrypted.plaintext)
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
