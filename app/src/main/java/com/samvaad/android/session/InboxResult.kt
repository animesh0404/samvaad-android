package com.samvaad.android.session

/**
 * Inbound mailbox-processing outcomes (slice: inbound decryption).
 *
 * Fixed safe results only — no server bodies, no stack traces, no key
 * material, and never plaintext except inside [InboxMessage] itself,
 * which callers hold in memory only. Plaintext is never persisted,
 * logged, or written anywhere by this layer.
 */
sealed interface InboxResult {
    /**
     * One mailbox batch processed entry-by-entry. [messages] holds at
     * most one plaintext per successfully decrypted entry (in fetch
     * order); [acked] holds the message IDs the server confirmed
     * deleted; [unacked] holds IDs whose plaintext was delivered exactly
     * once but whose ACK failed — the next fetch redelivers them into
     * the duplicate path, which authorizes the ACK without delivering
     * again; [skipped] explains every entry that produced no plaintext.
     */
    data class Completed(
        val messages: List<InboxMessage>,
        val acked: List<String>,
        val unacked: List<String>,
        val skipped: List<SkippedEntry>,
    ) : InboxResult

    /** Fetch-level failure: nothing was processed, nothing ACKed. */
    data class Failed(val kind: InboxFailure) : InboxResult
}

/** One successfully decrypted mailbox entry. [plaintext] is memory-only. */
data class InboxMessage(
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    val senderDeviceId: String,
    val envelopeType: String,
    val plaintext: ByteArray,
)

/** One entry that produced no plaintext. [reason] is a fixed token. */
data class SkippedEntry(
    val messageId: String,
    val reason: String,
)

/**
 * History-ingestion outcome for one server history item (no mailbox
 * ACK exists for history). `Stored` means the message is now durable
 * (freshly or already); `Duplicate` means a proven reprocessing with
 * the row present; `Skipped` carries the fail-closed reason.
 */
sealed interface HistoryIngestResult {
    data object Stored : HistoryIngestResult
    data object Duplicate : HistoryIngestResult
    data class Skipped(val reason: String) : HistoryIngestResult
}

sealed interface InboxFailure {
    /** Transport failure fetching the mailbox: retry the fetch later. */
    data object TransportRetryable : InboxFailure

    /** 401: caller must re-login through the existing gate. */
    data object Unauthorized : InboxFailure

    /** Malformed mailbox body, bad limit, or any other rejection. */
    data class Rejected(val reason: String) : InboxFailure
}
