package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.highestContiguous
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import java.io.IOException
import kotlinx.coroutines.CancellationException

/**
 * One launch-time reconciliation sweep over durable message state.
 *
 * Bounded, deterministic, headless recovery that repairs unfinished
 * local/server state after crash, force-stop, process death, lost HTTP
 * responses, or partial Room/Keystore progress. Safe to run once,
 * repeatedly, or after every restart: repeated execution converges
 * without duplicate messages, duplicate plaintext, ratchet forks,
 * cursor regression, or silent loss.
 *
 * Fixed order: (A) outbound `PENDING_SEAL`/`SEALED` recovery, (B)
 * mailbox/inbound recovery, (C) history gap filling, (D) cursor
 * reconciliation. Each branch fails closed on transport trouble and
 * never blocks the others. No background scheduling, no polling, no
 * secondary state machine: recovery reuses the sender/inbox paths and
 * the server as redelivery/idempotency arbiter.
 *
 * Construction is explicit; no DI. The [deviceLocks] holder MUST be the
 * same instance the sender and inbox share.
 */
class ReconciliationSweep(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val cryptoVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
    private val deviceLocks: SessionDeviceLocks = SessionDeviceLocks(),
    private val db: MessageDatabase,
    private val contentSealer: MessageContentSealer,
    private val bounds: SweepBounds = SweepBounds(),
) {
    private val sender = MessageSender(
        api = api,
        localMetadata = localMetadata,
        sessions = sessions,
        adapter = adapter,
        identityVault = cryptoVault,
        sessionVault = sessionVault,
        deviceLocks = deviceLocks,
        db = db,
        contentSealer = contentSealer,
    )
    private val inbox = InboxProcessor(
        api = api,
        localMetadata = localMetadata,
        sessions = sessions,
        adapter = adapter,
        cryptoVault = cryptoVault,
        sessionVault = sessionVault,
        deviceLocks = deviceLocks,
        db = db,
        contentSealer = contentSealer,
    )

    private fun dao() = db.messageDao()

    /**
     * Run one full sweep. Every branch is attempted even if an earlier
     * branch failed: branches touch disjoint recovery concerns and each
     * reports its own outcome below.
     */
    suspend fun sweep(
        session: AuthSession,
        serverAddress: String,
    ): SweepReport {
        val outbox = recoverOutbox(session, serverAddress)
        val inboxResult = recoverInbox(session, serverAddress)
        val history = reconcileHistories(session, serverAddress)
        val cursors = reconcileCursors(session, serverAddress)
        return SweepReport(
            outboxRecovered = outbox.outcomes,
            outboxSkippedDevices = outbox.skippedDevices,
            outboxError = outbox.error,
            inbox = inboxResult.result,
            inboxError = inboxResult.error,
            historyStored = history.stored,
            historyDuplicates = history.duplicates,
            historySkipped = history.skipped,
            historyError = history.error,
            cursorsAdvanced = cursors.advanced,
            cursorError = cursors.error,
        )
    }

    // ---- A. outbound ----

    private data class OutboxBranch(
        val outcomes: List<RecoverOutcome>,
        val skippedDevices: List<String>,
        val error: String?,
    )

    private suspend fun recoverOutbox(
        session: AuthSession,
        serverAddress: String,
    ): OutboxBranch {
        val rows = try {
            dao().pendingOutbox()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return OutboxBranch(emptyList(), emptyList(), "message-store-failed")
        }
        // Group by recipient so each device's rows recover under its own
        // lock, sequentially; devices stay independent of each other.
        val outcomes = mutableListOf<RecoverOutcome>()
        val skipped = mutableListOf<String>()
        for ((deviceId, deviceRows) in rows.groupBy { it.recipientDeviceId }.toSortedMap()) {
            if (deviceRows.isEmpty()) continue
            val username = try {
                sessions.read(deviceId)?.remoteUsername
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            } ?: run {
                // No address for this device (entry gone): leave its rows
                // for a future sweep once the session exists again.
                skipped.add(deviceId)
                continue
            }
            try {
                outcomes.addAll(sender.recoverUnsent(session, serverAddress, username, deviceId))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return OutboxBranch(outcomes, skipped, "outbox-recovery-failed")
            }
        }
        return OutboxBranch(outcomes, skipped, null)
    }

    // ---- B. inbound ----

    private data class InboxBranch(val result: InboxResult, val error: String?)

    private suspend fun recoverInbox(
        session: AuthSession,
        serverAddress: String,
    ): InboxBranch {
        // Snapshot pre-existing unacked rows: after the fetch, re-ACK
        // exactly these (plus any the fetch newly strands). ACKs are
        // idempotent, so already-gone server rows cost nothing.
        val preExisting = try {
            dao().unacked().map { it.messageId }.toSet()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return InboxBranch(
                InboxResult.Failed(InboxFailure.Rejected("message-store-failed")), "message-store-failed"
            )
        }
        val result = try {
            inbox.receive(session, serverAddress, bounds.mailboxLimit)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return InboxBranch(
                InboxResult.Failed(InboxFailure.Rejected("inbox-failed")), "inbox-failed"
            )
        }
        // Directly re-ACK pre-existing unacked rows: their server rows
        // may already be gone (mark-failure case) or still present
        // (ACK-failure case) — both converge through idempotent ACK.
        if (result is InboxResult.Completed) {
            reackUnacked(session, serverAddress, preExisting)
        }
        return InboxBranch(result, null)
    }

    private suspend fun reackUnacked(
        session: AuthSession,
        serverAddress: String,
        ids: Set<String>,
    ) {
        for (messageId in ids.sorted()) {
            val uuid = try {
                java.util.UUID.fromString(messageId)
            } catch (_: IllegalArgumentException) {
                continue
            }
            val ackedNow = try {
                api.ackMailbox(session, serverAddress, listOf(uuid))
                true
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
            if (!ackedNow) continue
            try {
                dao().markAcked(messageId)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Stays unacked for the next sweep; server already converged.
            }
        }
    }

    // ---- C. history ----

    private data class HistoryBranch(val stored: Int, val duplicates: Int, val skipped: Int, val error: String?)

    private suspend fun reconcileHistories(
        session: AuthSession,
        serverAddress: String,
    ): HistoryBranch {
        val conversationIds = try {
            dao().knownConversationIds()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return HistoryBranch(0, 0, 0, "message-store-failed")
        }
        var stored = 0
        var duplicates = 0
        var skipped = 0
        for (conversationId in conversationIds.sorted()) {
            ensureConversationRow(conversationId)
                ?: return HistoryBranch(stored, duplicates, skipped, "message-store-failed")
            val outcome = reconcileConversation(session, serverAddress, conversationId)
            if (outcome == null) return HistoryBranch(stored, duplicates, skipped, "history-failed")
            stored += outcome.stored
            duplicates += outcome.duplicates
            skipped += outcome.skipped
        }
        return HistoryBranch(stored, duplicates, skipped, null)
    }

    /**
     * Ensure a conversation row exists (preserving observed values), so
     * cursor bookkeeping below has a row even for send-only
     * conversations. Returns null only when the store itself fails.
     */
    private suspend fun ensureConversationRow(conversationId: String): ConversationEntity? {
        return try {
            val existing = dao().conversation(conversationId)
            if (existing != null) {
                val peak = dao().sequencesFor(conversationId).maxOrNull() ?: 0L
                if (peak > existing.lastSeenSequence) {
                    dao().upsertConversation(existing.copy(lastSeenSequence = peak))
                    dao().conversation(conversationId)
                } else {
                    existing
                }
            } else {
                val peak = dao().sequencesFor(conversationId).maxOrNull() ?: 0L
                val fresh = ConversationEntity(conversationId, peak, 0L)
                dao().upsertConversation(fresh)
                fresh
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        }
    }

    private data class ConversationOutcome(val stored: Int, val duplicates: Int, val skipped: Int)

    /**
     * Gap-fill one conversation from its contiguous point, bounded by
     * [SweepBounds.historyMaxPages]. Returns null on transport failure
     * (branch stops, state preserved for the next sweep).
     */
    private suspend fun reconcileConversation(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
    ): ConversationOutcome? {
        var stored = 0
        var duplicates = 0
        var skipped = 0
        var pages = 0
        while (pages < bounds.historyMaxPages) {
            val contiguous = try {
                highestContiguous(dao().sequencesFor(conversationId))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return null
            }
            val page = try {
                api.fetchHistory(session, serverAddress, conversationId, contiguous, bounds.historyLimit)
            } catch (e: CancellationException) {
                throw e
            } catch (_: EnrollException) {
                return null
            } catch (_: IOException) {
                return null
            }
            if (page.isEmpty()) break
            for (history in page) {
                when (inbox.ingestHistoryItem(history)) {
                    is HistoryIngestResult.Stored -> stored++
                    is HistoryIngestResult.Duplicate -> duplicates++
                    is HistoryIngestResult.Skipped -> skipped++
                }
            }
            pages++
            if (page.size < bounds.historyLimit) break
        }
        return ConversationOutcome(stored, duplicates, skipped)
    }

    // ---- D. cursors ----

    private data class CursorBranch(val advanced: Map<String, Long>, val error: String?)

    private suspend fun reconcileCursors(
        session: AuthSession,
        serverAddress: String,
    ): CursorBranch {
        val conversationIds = try {
            dao().knownConversationIds()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return CursorBranch(emptyMap(), "message-store-failed")
        }
        val advanced = mutableMapOf<String, Long>()
        for (conversationId in conversationIds.sorted()) {
            ensureConversationRow(conversationId)
                ?: return CursorBranch(advanced, "message-store-failed")
            // Read the server cursor first: advance only when local
            // contiguous state is strictly ahead of it. Never move it
            // backwards, never advance through a gap.
            val server = try {
                api.getSyncCursor(session, serverAddress, conversationId)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return CursorBranch(advanced, "cursor-fetch-failed")
            }
            val contiguous = try {
                highestContiguous(dao().sequencesFor(conversationId))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return CursorBranch(advanced, "message-store-failed")
            }
            // Converge the local cache upward to the authoritative server
            // value when they disagree — never regress it: the server
            // cursor is monotonic, so a lower read is stale, while a
            // higher one (e.g. after local state loss) is adopted.
            // Advancement below still requires contiguous past the server.
            val cached = try {
                dao().conversation(conversationId)?.cursorThrough ?: 0L
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return CursorBranch(advanced, "message-store-failed")
            }
            val converged = maxOf(cached, server.throughSequence)
            if (converged != cached) {
                try {
                    dao().setCursor(conversationId, converged)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    return CursorBranch(advanced, "message-store-failed")
                }
            }
            // Advance only past everything known (local cache and server
            // alike): a stale-low server read must trigger at most one
            // idempotent repeat, never a regression.
            if (contiguous <= converged) continue
            try {
                val moved = api.advanceSyncCursor(
                    session, serverAddress, conversationId, contiguous
                )
                dao().setCursor(conversationId, moved.throughSequence)
                advanced[conversationId] = moved.throughSequence
            } catch (e: CancellationException) {
                throw e
            } catch (_: EnrollException.Conflict) {
                // Lost a race or diverged: reread and converge the cache
                // upward (never regress it), never force, never roll back
                // messages.
                try {
                    val current = api.getSyncCursor(session, serverAddress, conversationId)
                    val known = dao().conversation(conversationId)?.cursorThrough ?: 0L
                    dao().setCursor(conversationId, maxOf(known, current.throughSequence))
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    return CursorBranch(advanced, "cursor-fetch-failed")
                }
            } catch (_: Exception) {
                return CursorBranch(advanced, "cursor-advance-failed")
            }
        }
        return CursorBranch(advanced, null)
    }
}
