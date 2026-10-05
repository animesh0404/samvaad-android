package com.samvaad.android.friends

/**
 * Friend-request and roster DTOs (Slice 14).
 *
 * Mirrors the server `FriendRequestDto` / `UserLookupDto` shapes. Server
 * timestamps are opaque strings here — display only, never parsed. IDs
 * stay strings like the rest of the client (no UUID typing at the edge).
 */
data class FriendRequestRecord(
    val requestId: String,
    val senderUserId: String,
    val senderUsername: String,
    val recipientUserId: String,
    val recipientUsername: String,
    /** PENDING, ACCEPTED, REJECTED, CANCELLED. */
    val status: String,
    val createdAt: String?,
    val respondedAt: String?,
)

/** One entry of `GET /api/friends` (same shape as user lookup). */
data class FriendEntry(
    val userId: String,
    val username: String,
)
