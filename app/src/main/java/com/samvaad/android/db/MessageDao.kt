package com.samvaad.android.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

/**
 * Slice 9 message-state queries — nothing more. Every method exists for
 * the crash-recovery state machines; no generic CRUD.
 *
 * Enum names are matched as string literals in SQL (`'OUT'`, `'SEALED'`
 * …); they must stay identical to [MessageDirection]/[SendState] entry
 * names. BLOB contents are never logged — these queries return rows to
 * callers that already own the sealed bytes, and no query prints them.
 */
@Dao
interface MessageDao {
    // ---- conversations ----

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertConversation(conversation: ConversationEntity)

    @Query("SELECT * FROM conversations WHERE conversationId = :conversationId")
    suspend fun conversation(conversationId: String): ConversationEntity?

    /** All locally known conversations, for history/cursor reconciliation. */
    @Query("SELECT * FROM conversations")
    suspend fun conversations(): List<ConversationEntity>

    /**
     * Every conversation with local state: tracked rows plus any
     * conversation referenced by message rows (e.g. outbox SENT rows
     * whose conversation was never observed inbound). The union keeps
     * history gap-filling reachable without inventing discovery.
     */
    @Query(
        "SELECT conversationId FROM conversations UNION " +
            "SELECT DISTINCT conversationId FROM messages WHERE conversationId != ''"
    )
    suspend fun knownConversationIds(): List<String>

    @Query("UPDATE conversations SET lastSeenSequence = :sequence WHERE conversationId = :conversationId")
    suspend fun setLastSeen(conversationId: String, sequence: Long)

    @Query("UPDATE conversations SET cursorThrough = :through WHERE conversationId = :conversationId")
    suspend fun setCursor(conversationId: String, through: Long)

    // ---- messages ----

    /**
     * Insert-or-ignore: a repeated `messageId` (redelivery, replay,
     * duplicate fetch) is absorbed and reports -1 instead of failing.
     * Returns the row ID, or -1 when the message was already present.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIgnore(message: MessageEntity): Long

    @Query("SELECT * FROM messages WHERE messageId = :messageId")
    suspend fun byMessageId(messageId: String): MessageEntity?

    @Query("SELECT * FROM messages WHERE requestId = :requestId")
    suspend fun byRequestId(requestId: String): MessageEntity?

    /** Outbound rows not yet accepted: `PENDING_SEAL` (re-encrypt/
     * supersede path) and `SEALED` (identical-resubmit path). The
     * reconciler branches on [MessageEntity.sendState] per row. */
    @Query("SELECT * FROM messages WHERE direction = 'OUT' AND sendState IN ('PENDING_SEAL', 'SEALED')")
    suspend fun pendingOutbox(): List<MessageEntity>

    /** Inbound rows decrypted and sealed but not yet acknowledged. */
    @Query("SELECT * FROM messages WHERE direction = 'IN' AND acked = 0")
    suspend fun unacked(): List<MessageEntity>

    @Query("UPDATE messages SET sendState = 'SEALED' WHERE messageId = :messageId")
    suspend fun markSealed(messageId: String): Int

    @Query("UPDATE messages SET sendState = 'SENT' WHERE messageId = :messageId")
    suspend fun markSent(messageId: String): Int

    /**
     * Accept a submitted row: marks SENT and records the server-assigned
     * identity in the same statement, so the local row can later join
     * server history (which keys on the server ID, not ours).
     */
    @Query(
        "UPDATE messages SET sendState = 'SENT', serverMessageId = :serverMessageId, " +
            "conversationId = :conversationId, sequenceNumber = :sequenceNumber, " +
            "serverTimestamp = :serverTimestamp WHERE messageId = :messageId"
    )
    suspend fun markAccepted(
        messageId: String,
        serverMessageId: String,
        conversationId: String,
        sequenceNumber: Long,
        serverTimestamp: String,
    ): Int

    @Query("UPDATE messages SET acked = 1 WHERE messageId = :messageId")
    suspend fun markAcked(messageId: String): Int

    /**
     * Drop one row. Used only to supersede a `PENDING_SEAL` attempt whose
     * session was never committed: its requestId never reached the
     * server, so forgetting it is safe. Never called for `SEALED` rows
     * (those resubmit identically instead).
     */
    @Query("DELETE FROM messages WHERE messageId = :messageId")
    suspend fun deleteMessage(messageId: String): Int

    @Query(
        "SELECT * FROM messages WHERE conversationId = :conversationId " +
            "AND sequenceNumber > :afterSequence ORDER BY sequenceNumber ASC LIMIT :limit"
    )
    suspend fun historyPage(
        conversationId: String,
        afterSequence: Long,
        limit: Int,
    ): List<MessageEntity>

    /** Ascending stored sequences for one conversation (contiguity input). */
    @Query("SELECT sequenceNumber FROM messages WHERE conversationId = :conversationId ORDER BY sequenceNumber ASC")
    suspend fun sequencesFor(conversationId: String): List<Long>
}

/**
 * Highest locally stored sequence forming an unbroken run starting at
 * sequence 1 (server sequences start at 1; 0 means "nothing stored").
 * A gap stops advancement: callers must gap-fill before trusting a
 * higher number, otherwise a bounded server buffer could evict the
 * missing rows into permanent loss.
 *
 * Documented edge behavior (no silent assumption):
 * - empty list, or a set not containing 1, yields 0;
 * - `listOf(1, 2, 3)` yields 3;
 * - `listOf(1, 2, 3, 5)` yields 3;
 * - `listOf(1, 3)` yields 1;
 * - `listOf(5, 6)` yields 0 (prefix missing; gap handling belongs to
 *   the reconciliation step, not to this pure function).
 */
fun highestContiguous(sequences: List<Long>): Long {
    val sorted = sequences.sorted()
    if (sorted.isEmpty() || sorted.first() != 1L) return 0L
    var contiguous = 1L
    for (sequence in sorted.drop(1)) {
        if (sequence == contiguous + 1) {
            contiguous = sequence
        } else if (sequence > contiguous + 1) {
            break
        }
        // Duplicates (sequence <= contiguous) are absorbed, not advanced.
    }
    return contiguous
}
