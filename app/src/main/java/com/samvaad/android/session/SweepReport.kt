package com.samvaad.android.session

/**
 * Launch-time sweep outcome (slice: durable reconciliation).
 *
 * Fixed safe shape only — counts, identifiers, and typed branch
 * results; no key material, no plaintext, no ciphertext, no tokens.
 * Every branch reports independently: one branch's failure never hides
 * another's progress.
 */
data class SweepReport(
    /** Per-row outbox recovery outcomes (resubmitted / superseded / failed). */
    val outboxRecovered: List<RecoverOutcome>,
    /** Recipient devices whose rows were skipped (no session entry). */
    val outboxSkippedDevices: List<String>,
    /** Non-null when the outbox branch itself could not run. */
    val outboxError: String?,
    /** Mailbox fetch + per-entry processing outcome. */
    val inbox: InboxResult,
    /** Non-null when the inbox branch itself could not run. */
    val inboxError: String?,
    /** History items newly persisted this sweep. */
    val historyStored: Int,
    /** History items already durable (insert-ignore / duplicate path). */
    val historyDuplicates: Int,
    /** History items skipped fail-closed. */
    val historySkipped: Int,
    /** Non-null when history reconciliation stopped early. */
    val historyError: String?,
    /** Conversations whose cursor actually advanced, with new values. */
    val cursorsAdvanced: Map<String, Long>,
    /** Non-null when cursor reconciliation stopped early. */
    val cursorError: String?,
)

/**
 * Deterministic launch-time work bounds. Small and fixed: the sweep
 * must finish quickly and never schedule itself.
 */
data class SweepBounds(
    /** Mailbox entries pulled per sweep (single fetch). */
    val mailboxLimit: Int = 20,
    /** History items per page fetch. */
    val historyLimit: Int = 20,
    /** History pages fetched per conversation per sweep. */
    val historyMaxPages: Int = 3,
)
