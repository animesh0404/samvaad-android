package com.samvaad.android.session

import org.json.JSONException
import org.json.JSONObject

/**
 * Encrypted history-sync payload (Slice 12).
 *
 * One JSON object per transferred message, encrypted by the Primary
 * with the existing Primary→Companion Signal session and uploaded as
 * opaque batch ciphertext. The Companion decrypts it, validates every
 * binding below, then seals the inner plaintext and persists a durable
 * row carrying the ORIGINAL message identity.
 *
 * This format asserts Primary authority, not original authorship: the
 * Companion cryptographically authenticates the Primary as the sync
 * sender (Signal session + pinned identity) and accepts the enclosed
 * original-sender fields as the Primary's assertion (ADR 0026). No
 * second signature scheme exists by design.
 */
data class SyncPayload(
    val conversationId: String,
    val messageId: String,
    val sequenceNumber: Long,
    /** Original authoring device (display + provenance, not session lookup). */
    val senderDeviceId: String,
    /** Original recipient device (display + provenance, not session lookup). */
    val recipientDeviceId: String,
    val serverTimestamp: String,
    /** Raw message bytes (opened from the Primary's sealed content). */
    val plaintext: ByteArray,
    /** Primary's highest contiguous durable sequence for the conversation. */
    val frontier: Long,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SyncPayload) return false
        return conversationId == other.conversationId
            && messageId == other.messageId
            && sequenceNumber == other.sequenceNumber
            && senderDeviceId == other.senderDeviceId
            && recipientDeviceId == other.recipientDeviceId
            && serverTimestamp == other.serverTimestamp
            && plaintext.contentEquals(other.plaintext)
            && frontier == other.frontier
    }

    override fun hashCode(): Int {
        var result = conversationId.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + senderDeviceId.hashCode()
        result = 31 * result + recipientDeviceId.hashCode()
        result = 31 * result + serverTimestamp.hashCode()
        result = 31 * result + plaintext.contentHashCode()
        result = 31 * result + frontier.hashCode()
        return result
    }
}

private const val SYNC_PAYLOAD_VERSION = 1

/** Builds the canonical encrypted payload bytes for one message. */
fun buildSyncPayload(
    conversationId: String,
    messageId: String,
    sequenceNumber: Long,
    senderDeviceId: String,
    recipientDeviceId: String,
    serverTimestamp: String,
    plaintext: ByteArray,
    frontier: Long,
): ByteArray {
    require(conversationId.isNotBlank())
    require(messageId.isNotBlank())
    require(sequenceNumber >= 1)
    require(senderDeviceId.isNotBlank())
    require(recipientDeviceId.isNotBlank())
    require(plaintext.isNotEmpty())
    require(frontier >= sequenceNumber)
    return JSONObject()
        .put("v", SYNC_PAYLOAD_VERSION)
        .put("conversationId", conversationId)
        .put("messageId", messageId)
        .put("sequenceNumber", sequenceNumber)
        .put("senderDeviceId", senderDeviceId)
        .put("recipientDeviceId", recipientDeviceId)
        .put("serverTimestamp", serverTimestamp)
        .put("plaintextBase64", com.samvaad.android.crypto.SpikeCryptoMaterial.encodeBase64(plaintext))
        .put("frontier", frontier)
        .toString()
        .toByteArray(Charsets.UTF_8)
}

/**
 * Parses and validates a decrypted sync payload. Any structural
 * problem (including a version other than exactly 1) fails the whole
 * item: the caller must skip it fail-closed, never ingest it.
 */
@Throws(SyncPayloadMalformedException::class)
fun parseSyncPayload(bytes: ByteArray): SyncPayload {
    try {
        val json = JSONObject(bytes.toString(Charsets.UTF_8))
        if (json.getInt("v") != SYNC_PAYLOAD_VERSION) {
            throw SyncPayloadMalformedException("unsupported sync payload version")
        }
        val plaintext = com.samvaad.android.crypto.SpikeCryptoMaterial
            .decodeBase64(json.getString("plaintextBase64"))
        if (plaintext.isEmpty()) throw SyncPayloadMalformedException("empty sync plaintext")
        val sequenceNumber = json.getLong("sequenceNumber")
        if (sequenceNumber < 1) throw SyncPayloadMalformedException("bad sync sequence")
        val frontier = json.getLong("frontier")
        if (frontier < sequenceNumber) throw SyncPayloadMalformedException("frontier below sequence")
        val payload = SyncPayload(
            conversationId = json.getString("conversationId"),
            messageId = json.getString("messageId"),
            sequenceNumber = sequenceNumber,
            senderDeviceId = json.getString("senderDeviceId"),
            recipientDeviceId = json.getString("recipientDeviceId"),
            serverTimestamp = json.getString("serverTimestamp"),
            plaintext = plaintext,
            frontier = frontier,
        )
        if (payload.conversationId.isBlank() || payload.messageId.isBlank()
            || payload.senderDeviceId.isBlank() || payload.recipientDeviceId.isBlank()
        ) {
            throw SyncPayloadMalformedException("blank sync identity field")
        }
        return payload
    } catch (e: JSONException) {
        throw SyncPayloadMalformedException("malformed sync payload", e)
    } catch (e: IllegalArgumentException) {
        throw SyncPayloadMalformedException("malformed sync payload", e)
    }
}

/** A decrypted sync payload that fails structural validation. Never ingested. */
class SyncPayloadMalformedException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)
