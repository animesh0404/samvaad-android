package com.samvaad.android.enroll

/**
 * Message-submission DTOs (slice: outbound encrypted message submission).
 *
 * Wire mirror of `POST /api/e2ee/messages` at baseline `164463da`.
 * Exactly one envelope per request in this slice; the server derives the
 * conversation and assigns the sequence number. `ciphertext` is
 * standard-Base64 of opaque libsignal message bytes — never inspected.
 * `org.json` mapping lives in [HttpE2eeDeviceApi]. No libsignal types, no
 * private material, no plaintext.
 */

/** One recipient envelope inside a submit request. */
data class MessageEnvelopeSubmit(
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val envelopeType: String,
    val ciphertextBase64: String,
)

/**
 * Successful submit outcome. [createdNew] distinguishes `201 Created`
 * from `200 OK` (identical `messageRequestId` replay).
 */
data class SubmitMessageResult(
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    val serverTimestamp: String,
    val acceptedRecipientDevices: List<String>,
    val createdNew: Boolean,
)
