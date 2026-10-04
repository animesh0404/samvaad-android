package com.samvaad.android.enroll

import java.util.UUID

/**
 * Primary-to-Companion history-sync DTOs (Slice 12 transport slice).
 *
 * Wire mirrors the live server sync contract:
 * `POST /api/e2ee/sync-history/batches` accepts one Companion device,
 * one conversation, and an ordered item list (201 new, 200 exact
 * replay, 409 divergent retry);
 * `GET /api/e2ee/sync-history/batches?conversationId=&afterSequence=&limit=`
 * returns this Companion's pending items ascending by sequenceNumber;
 * `POST /api/e2ee/sync-history/ack` evicts at or below a prefix and
 * returns the evicted count. `org.json` mapping lives in
 * [HttpE2eeDeviceApi]. No libsignal types, no private material, no
 * plaintext: item ciphertext is the Primary's Signal-session bytes for
 * exactly one Companion device.
 */

/** One opaque sync item in either direction (upload request / fetch response). */
data class SyncBatchItem(
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    /** Uploading Primary device; resolves the decryption session on fetch. */
    val senderDeviceId: String,
    /** Real libsignal encoding (`PREKEY_INIT` / `RATCHET`) of the bytes. */
    val envelopeType: String,
    val ciphertextBase64: String,
)

/** Primary batch upload for one Companion device and one conversation. */
data class SyncUploadRequest(
    val syncBatchId: UUID,
    val recipientDeviceId: String,
    val conversationId: String,
    val fromSequence: Long,
    val frontier: Long,
    val items: List<SyncBatchItem>,
)

/** Upload outcome. [createdNew] false means exact receipt replay. */
data class SyncUploadResult(
    val syncBatchId: UUID,
    val acceptedCount: Int,
    val createdNew: Boolean,
)

/** Prefix-acknowledgement outcome: rows evicted server-side. */
data class SyncAckResult(
    val evicted: Int,
)
