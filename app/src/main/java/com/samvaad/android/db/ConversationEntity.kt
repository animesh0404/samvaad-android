package com.samvaad.android.db

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Durable per-conversation facts (slice: durable message state).
 *
 * No participant/user model yet: the server derives conversation
 * identity and the client addresses history strictly by
 * [conversationId]. [lastSeenSequence] is the highest sequence number
 * observed locally; [cursorThrough] caches the server cursor this
 * device last asserted (monotonic server-side). Non-negative by
 * construction; server sequences start at 1, so 0 means "nothing yet".
 */
@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey
    val conversationId: String,
    val lastSeenSequence: Long = 0L,
    val cursorThrough: Long = 0L,
)
