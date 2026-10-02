package com.samvaad.android.enroll

/**
 * Mailbox DTOs (slice: inbound mailbox consumption + Signal decryption).
 *
 * Wire mirror of `GET /api/e2ee/mailbox` and `POST /api/e2ee/mailbox/ack`
 * at baseline `164463da`. The mailbox returns a bare JSON array of
 * per-recipient ciphertext items in server acceptance order — no entry
 * IDs, no redelivery flags, no pagination tokens. ACK takes message IDs;
 * unknown/foreign IDs are ignored by the server and the response carries
 * only the deleted-row count. `org.json` mapping lives in
 * [HttpE2eeDeviceApi]. No libsignal types, no private material, no
 * plaintext.
 */

/** One undelivered ciphertext item from the mailbox fetch. */
data class MailboxItem(
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    val senderUserId: String,
    val senderDeviceId: String,
    val envelopeType: String,
    val ciphertextBase64: String,
    val serverTimestamp: String,
)
