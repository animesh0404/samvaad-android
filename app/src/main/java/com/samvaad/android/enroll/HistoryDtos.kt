package com.samvaad.android.enroll

/**
 * History + sync-cursor DTOs (slice: history/cursor API boundary).
 *
 * Wire mirrors at baseline `164463da`:
 * `GET /api/e2ee/conversations/{id}/messages?afterSequence=&limit=`
 * returns a bare JSON array of per-device ciphertext items (same 8-field
 * shape the mailbox uses, ascending by sequenceNumber, scoped to the
 * requesting device — a device receives only its own envelopes);
 * `GET /api/e2ee/sync?conversationId=` and `PUT /api/e2ee/sync` carry
 * `{conversationId, throughSequence}` (absent cursor reads as 0).
 * `org.json` mapping lives in [HttpE2eeDeviceApi]. No libsignal types,
 * no private material, no plaintext.
 */

/**
 * One durable history item. Same wire shape as [MailboxItem] by server
 * design, kept as its own type so each endpoint's contract stays
 * explicit (the sources differ: undelivered queue vs durable envelopes).
 */
data class HistoryItem(
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    val senderUserId: String,
    val senderDeviceId: String,
    val envelopeType: String,
    val ciphertextBase64: String,
    val serverTimestamp: String,
)

/** Per-device/per-conversation asserted-processed marker. */
data class SyncCursor(
    val conversationId: String,
    val throughSequence: Long,
)
