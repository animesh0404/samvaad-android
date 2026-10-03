package com.samvaad.android.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Message direction across the local device boundary. */
enum class MessageDirection {
    IN,
    OUT,
}

/**
 * Outbound pipeline state. Rows areappend-only through these states;
 * a `SEALED` row's bytes/requestId are never mutated (a new logical
 * message always inserts a new row) so server idempotent replay stays
 * well-defined. Inbound rows leave this null and use [MessageEntity.acked].
 */
enum class SendState {
    PENDING_SEAL,
    SEALED,
    SENT,
}

/**
 * Durable message facts (slice: durable message state).
 *
 * Dedupe key is [messageId] everywhere: re-inserting a known message is
 * absorbed, never duplicated. [requestId] is unique when present
 * (outbound rows only; inbound rows leave it null) so an accidental
 * request-ID reuse fails the insert loudly instead of forking server
 * idempotency. Same `(conversationId, sequenceNumber)` under different
 * message IDs is stored as-is — the server contract guarantees sequence
 * uniqueness, and the local layer does not second-guess it.
 *
 * BLOB columns hold opaque bytes only: [ciphertext] is Signal transport
 * bytes, [plaintextSealed] is [com.samvaad.android.crypto.MessageContentSealer]
 * output. There is deliberately no plaintext, key-material, or token
 * column. Both BLOBs are nullable because a row is inserted before all
 * of its bytes necessarily exist yet (e.g. an outbound row is created
 * around encryption, not before it).
 *
 * [serverMessageId] is the server-assigned message identity returned on
 * submit accept. It is distinct from the client-generated primary key:
 * the server mints its own IDs, so joining local rows to server history
 * later requires keeping both. Null until the server accepts the row.
 */
@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["conversationId", "sequenceNumber"]),
        Index(value = ["requestId"], unique = true),
    ],
)
data class MessageEntity(
    @PrimaryKey
    val messageId: String,
    val conversationId: String,
    val sequenceNumber: Long,
    val direction: MessageDirection,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val envelopeType: String,
    val ciphertext: ByteArray?,
    val plaintextSealed: ByteArray?,
    val sendState: SendState?,
    val acked: Boolean = false,
    val requestId: String?,
    val serverMessageId: String? = null,
    val serverTimestamp: String,
    val createdAt: Long,
)
