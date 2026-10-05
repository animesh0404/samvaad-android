package com.samvaad.android.friends

import com.samvaad.android.AuthSession
import java.io.IOException

/**
 * Friend-request HTTP boundary (Slice 14: send + incoming + accept).
 *
 * Mirrors the [com.samvaad.android.AuthApi] style: the interface is the
 * seam tests fake; callers never touch HTTP. All calls use the
 * authenticated session's access token; the session itself is never
 * persisted here.
 *
 * Error taxonomy carries no server bodies — UI maps each subtype to a
 * fixed safe string.
 */
sealed class FriendException(message: String, cause: Throwable? = null) :
    IOException(message, cause) {
    /** Transport failure, timeout, or malformed response. */
    class Transport(cause: Throwable? = null) : FriendException("transport failure", cause)

    /** 401 or missing/invalid auth. Caller should re-login. */
    class Unauthorized : FriendException("unauthorized")

    /** 400 validation/server rejection of the request shape. */
    class BadRequest : FriendException("bad request")

    /**
     * 403: self-request on send, or non-recipient on accept/reject.
     * Never blind-retried as the same caller.
     */
    class Forbidden : FriendException("forbidden")

    /** 404: unknown username (send/lookup) or unknown request id. */
    class NotFound : FriendException("not found")

    /**
     * 409: duplicate pending request (either direction), already
     * friends, or request no longer PENDING. Converge by re-listing,
     * never blind-retry.
     */
    class Conflict : FriendException("conflict")

    /** Any other unexpected server rejection. */
    class ServerRejected : FriendException("server rejected")
}

interface FriendsApi {
    /**
     * GET /api/users/lookup?username=. Returns the user row for an
     * exact (case-insensitive) username match.
     *
     * @throws FriendException.NotFound unknown username.
     */
    @Throws(IOException::class)
    suspend fun lookupUser(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): FriendEntry

    /**
     * POST /api/friend-requests with `{"username": ...}`. Creates a
     * PENDING request from the caller to the named user (201).
     *
     * @throws FriendException.Forbidden self-request (403).
     * @throws FriendException.NotFound unknown username (404).
     * @throws FriendException.Conflict already pending or already
     *   friends (409) — converge by re-listing.
     */
    @Throws(IOException::class)
    suspend fun sendRequest(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): FriendRequestRecord

    /**
     * GET /api/friend-requests/incoming. PENDING requests addressed to
     * the caller (possibly empty).
     */
    @Throws(IOException::class)
    suspend fun listIncoming(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendRequestRecord>

    /**
     * GET /api/friend-requests/outgoing. PENDING requests sent by the
     * caller (possibly empty). UI-deferred this slice; exposed so a
     * later slice can show cancel affordances without a new boundary.
     */
    @Throws(IOException::class)
    suspend fun listOutgoing(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendRequestRecord>

    /**
     * POST /api/friend-requests/{requestId}/accept (empty body).
     * Recipient-only; transitions PENDING → ACCEPTED.
     *
     * @throws FriendException.Forbidden non-recipient (403).
     * @throws FriendException.NotFound unknown request (404).
     * @throws FriendException.Conflict no longer PENDING (409).
     */
    @Throws(IOException::class)
    suspend fun acceptRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord

    /**
     * POST /api/friend-requests/{requestId}/reject (empty body).
     * Recipient-only; transitions PENDING → REJECTED. Same taxonomy as
     * [acceptRequest].
     */
    @Throws(IOException::class)
    suspend fun rejectRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord

    /**
     * POST /api/friend-requests/{requestId}/cancel (empty body).
     * Sender-only; transitions PENDING → CANCELLED. UI-deferred this
     * slice; exposed for the same reason as [listOutgoing].
     *
     * @throws FriendException.Forbidden non-sender (403).
     * @throws FriendException.NotFound unknown request (404).
     * @throws FriendException.Conflict no longer PENDING (409).
     */
    @Throws(IOException::class)
    suspend fun cancelRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord

    /**
     * GET /api/friends. Accepted friends of the caller, sorted by
     * username (possibly empty).
     */
    @Throws(IOException::class)
    suspend fun listFriends(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendEntry>
}
