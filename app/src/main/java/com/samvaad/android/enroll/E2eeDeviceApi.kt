package com.samvaad.android.enroll

import com.samvaad.android.AuthSession
import java.io.IOException

/**
 * E2EE device-enrollment HTTP boundary (first-device bootstrap slice).
 *
 * Mirrors the [com.samvaad.android.AuthApi] style: the interface is the seam
 * tests fake; callers never touch HTTP. All calls use the authenticated
 * session's access token; the session itself is never persisted here.
 *
 * Error taxonomy carries no server bodies — UI maps each subtype to a fixed
 * safe string. [RecoveryRequired] preserves the stable
 * `E2EE_RECOVERY_REQUIRED` reason internally.
 */
sealed class EnrollException(message: String, cause: Throwable? = null) :
    IOException(message, cause) {
    /** Transport failure, timeout, or malformed response. */
    class Transport(cause: Throwable? = null) : EnrollException("transport failure", cause)

    /**
     * The server answered 2xx with a body that does not parse as the
     * documented contract. Distinct from [Transport] (no usable response
     * arrived at all): callers must not treat the attempt as
     * known-unconsumed — for claim, the OTPK may already be burned, so
     * any retry claims fresh.
     */
    class Malformed(cause: Throwable? = null) : EnrollException("malformed response", cause)

    /** 401 or missing/invalid auth. Caller should re-login. */
    class Unauthorized : EnrollException("unauthorized")

    /** 400 validation/server rejection of the request shape. */
    class BadRequest : EnrollException("bad request")

    /** 403 with reason `E2EE_RECOVERY_REQUIRED` (or other 403). */
    class RecoveryRequired : EnrollException("recovery required")

    /**
     * 403 on device-discovery endpoints (directory/claim): caller is not a
     * friend of the target user. Never blind-retried as the same caller.
     */
    class Forbidden : EnrollException("forbidden")

    /**
     * 404 on device-discovery endpoints: unknown user (directory) or
     * unknown/inactive (PENDING/REVOKED-masked) device (claim). The caller
     * must re-discover rather than retry the same target.
     */
    class NotFound : EnrollException("not found")

    /** 409 conflict (e.g. identity already enrolled). Reconcile, never blind-retry. */
    class Conflict : EnrollException("conflict")

    /** Any other unexpected server rejection. */
    class ServerRejected : EnrollException("server rejected")
}

interface E2eeDeviceApi {
    /**
     * POST /api/e2ee/devices. Requires an UNBOUND session; binds it on 201.
     * @throws EnrollException on any non-201 outcome.
     */
    @Throws(IOException::class)
    suspend fun enroll(session: AuthSession, serverAddress: String, request: EnrollRequest): EnrollResult

    /**
     * PUT /api/e2ee/devices/{deviceId}/one-time-prekeys. Requires the
     * session bound to [deviceId] and an ACTIVE device. Batch must hold
     * exactly 100 entries.
     */
    @Throws(IOException::class)
    suspend fun uploadOneTimePrekeys(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        batch: List<OneTimePrekeyUpload>,
    )

    /** GET /api/e2ee/devices. Owner list for reconciliation. */
    @Throws(IOException::class)
    suspend fun listDevices(session: AuthSession, serverAddress: String): DeviceList

    /**
     * POST /api/e2ee/devices/{deviceId}/approve (empty body). Approves an
     * owned PENDING device. The caller session must be bound to an owned
     * ACTIVE device — the pending device's own session can never approve
     * itself. Returns the approved row (200; idempotent when already
     * ACTIVE).
     *
     * @throws EnrollException.NotFound unknown device id.
     * @throws EnrollException.Conflict target REVOKED (409).
     * @throws EnrollException.ServerRejected approval not permitted (403).
     */
    @Throws(IOException::class)
    suspend fun approveDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): DeviceRecord

    /**
     * POST /api/e2ee/devices/{deviceId}/bind with `{"recoveryCode": ...}`.
     * Binds the current unbound session to an existing owned ACTIVE
     * device. Creates no device, accepts no key material, preserves the
     * existing identity/signalDeviceId. Returns the bound row (200).
     *
     * The code is single-use: callers must never blind-retry after an
     * uncertain transport outcome — reconcile through [listDevices] first.
     * The code is passed transiently and never stored here.
     *
     * @throws EnrollException.Conflict session already bound, or target
     * inactive (both 409 — converge through [listDevices]).
     * @throws EnrollException.ServerRejected wrong/used code (403).
     */
    @Throws(IOException::class)
    suspend fun bindDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        recoveryCode: String,
    ): DeviceRecord

    /**
     * POST /api/e2ee/devices/{deviceId}/attach/begin (empty body).
     * Starts the proof-of-possession handshake that binds the current
     * session to an already-enrolled owned ACTIVE device. Consumes no
     * recovery code and creates no device.
     *
     * [AttachBegin.AlreadyBound] is the idempotent success when the
     * session is already bound to [deviceId] — no cryptography needed.
     * Otherwise the server returns a single-use challenge for
     * [completeAttach].
     *
     * @throws EnrollException.Conflict session bound to a different
     * device, or target inactive (both 409 — converge through
     * [listDevices], never blind-retry).
     * @throws EnrollException.ServerRejected not the owner (403).
     * @throws EnrollException.NotFound unknown device id (404).
     */
    @Throws(IOException::class)
    suspend fun beginAttach(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): AttachBegin

    /**
     * POST /api/e2ee/devices/{deviceId}/attach/complete with
     * `{"challengeId": ..., "proof": ...}`.
     *
     * The proof is SHA-256 over the domain-separated X25519 shared
     * secret, device id, and session id (see the server `AttachProof`
     * spec, mirrored byte-for-byte by the crypto adapter). Returns the
     * bound row (200). The challenge is consumed on success; a mismatch
     * leaves the session unbound.
     *
     * @throws EnrollException.BadRequest unknown/expired/mismatched
     * challenge (400 — start over with [beginAttach], exactly once).
     * @throws EnrollException.ServerRejected proof mismatch or not the
     * owner (403 — surface, never retry the same proof).
     * @throws EnrollException.Conflict session bound elsewhere, or
     * target inactive (409 — converge through [listDevices]).
     */
    @Throws(IOException::class)
    suspend fun completeAttach(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        challengeId: String,
        proofBase64: String,
    ): DeviceRecord

    /**
     * POST /api/e2ee/recovery/enroll with
     * `{"recoveryCode": ..., "device": {...}}`. Creates a NEW ACTIVE
     * device from fresh public material, consuming one recovery code
     * atomically with creation. Returns the created row (201); the caller
     * still uploads the 100-OTPK batch afterwards. Never resurrects a
     * revoked row.
     *
     * Same single-use/reconcile-first rules as [bindDevice].
     */
    @Throws(IOException::class)
    suspend fun recoverEnroll(
        session: AuthSession,
        serverAddress: String,
        recoveryCode: String,
        request: EnrollRequest,
    ): DeviceRecord

    /**
     * GET /api/e2ee/users/{username}/devices. Friendship-gated recipient
     * directory (ACTIVE devices only, possibly empty). Claim does not
     * require session→device binding. @throws EnrollException with
     * [EnrollException.Forbidden] for non-friends and
     * [EnrollException.NotFound] for unknown users.
     */
    @Throws(IOException::class)
    suspend fun listRecipientDevices(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): List<RecipientDeviceRecord>

    /**
     * POST /api/e2ee/devices/{deviceId}/one-time-prekeys/claim.
     * Atomically consumes one EC one-time prekey ([requestId] makes the
     * claim replay-safe; every NEW attempt must use a fresh UUID).
     * A null [ClaimedDeviceBundle.oneTimePrekey] is the signed-prekey
     * fallback, not an error.
     */
    @Throws(IOException::class)
    suspend fun claimOneTimePrekey(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        requestId: java.util.UUID,
    ): ClaimedDeviceBundle

    /**
     * POST /api/e2ee/messages. Submits one logical message (exactly one
     * envelope in this slice). Every `senderDeviceId` must equal the
     * session-bound device or the server returns 403; the recipient must
     * be an ACTIVE friend device or the server returns 404/403.
     *
     * Idempotency: resubmitting the same `requestId` with byte-identical
     * envelopes replays the original response ([SubmitMessageResult]
     * with `createdNew=false`); the same `requestId` with different
     * content is a 409 [EnrollException.Conflict].
     */
    @Throws(IOException::class)
    suspend fun submitMessage(
        session: AuthSession,
        serverAddress: String,
        requestId: java.util.UUID,
        envelopes: List<MessageEnvelopeSubmit>,
    ): SubmitMessageResult

    /**
     * GET /api/e2ee/mailbox?limit=N. Returns this session-bound device's
     * undelivered ciphertext in stable server acceptance order (bare JSON
     * array, possibly empty). [limit] is 1..100. Sessions without a bound
     * device see an empty mailbox (HTTP 200), never an error.
     */
    @Throws(IOException::class)
    suspend fun fetchMailbox(
        session: AuthSession,
        serverAddress: String,
        limit: Int = 20,
    ): List<MailboxItem>

    /**
     * POST /api/e2ee/mailbox/ack with `{"messageIds": [...]}`. Deletes
     * only this bound device's entries; unknown/foreign IDs acknowledge
     * nothing. Returns the deleted-row count. Idempotent: repeating an
     * ACK returns 0 for already-deleted entries. Requires the session
     * bound to an ACTIVE device (else 403).
     */
    @Throws(IOException::class)
    suspend fun ackMailbox(
        session: AuthSession,
        serverAddress: String,
        messageIds: List<java.util.UUID>,
    ): Int

    /**
     * GET /api/e2ee/conversations/{conversationId}/messages?afterSequence=&limit=.
     * Returns this device's durable envelopes after [afterSequence],
     * ascending, participant-only. [afterSequence] is 0-based (0 fetches
     * from the start); [limit] is 1..100. Readable after mailbox ACK;
     * ACK never deletes history. Unknown conversation is 404,
     * non-participant is 403.
     */
    @Throws(IOException::class)
    suspend fun fetchHistory(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        afterSequence: Long,
        limit: Int,
    ): List<HistoryItem>

    /**
     * GET /api/e2ee/sync?conversationId=. Returns this device's stored
     * cursor for the conversation; an absent cursor reads as 0.
     * Read-only: fetching history or mailboxes never moves the cursor.
     */
    @Throws(IOException::class)
    suspend fun getSyncCursor(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
    ): SyncCursor

    /**
     * PUT /api/e2ee/sync with `{conversationId, throughSequence}`.
     * Explicit client assertion of durable processing — the only writer.
     * [throughSequence] must satisfy 0 <= n <= conversation last
     * sequence: backward moves and beyond-last advances are 409, repeats
     * are safe. Callers must advance only through the highest contiguous
     * locally durable sequence, never through a gap.
     */
    @Throws(IOException::class)
    suspend fun advanceSyncCursor(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        throughSequence: Long,
    ): SyncCursor

    /**
     * GET /api/conversations/direct?limit=&offset=. Lists conversations
     * the authenticated user participates in, newest first. Used by
     * history sync so a fresh Companion with no local rows can still
     * discover conversations to pull. Returns conversation IDs only;
     * history content still comes from sync fetch.
     */
    @Throws(IOException::class)
    suspend fun listConversations(
        session: AuthSession,
        serverAddress: String,
        limit: Int = 20,
    ): List<String>

    /**
     * POST /api/e2ee/sync-history/batches. Primary-only upload of one
     * Companion's history batch for one conversation. Returns 201 with
     * `createdNew=true` for a newly accepted batch, 200 with
     * `createdNew=false` for an exact idempotent replay.
     *
     * @throws EnrollException.Conflict on divergent batch-id reuse (409).
     * @throws EnrollException.Forbidden when the caller is not an ACTIVE
     *   PRIMARY or the recipient is not an ACTIVE same-user COMPANION (403).
     * @throws EnrollException.NotFound unknown conversation/device (404).
     * @throws EnrollException.BadRequest malformed batch (400).
     */
    @Throws(IOException::class)
    suspend fun uploadSyncBatch(
        session: AuthSession,
        serverAddress: String,
        request: SyncUploadRequest,
    ): SyncUploadResult

    /**
     * GET /api/e2ee/sync-history/batches?conversationId=&afterSequence=&limit=.
     * Companion-only fetch of this device's pending sync items for one
     * conversation, ascending by sequenceNumber. Empty is normal (nothing
     * pending). [limit] is 1..100.
     *
     * @throws EnrollException.Forbidden when the caller is not an ACTIVE
     *   COMPANION with a live PRIMARY relationship (403).
     * @throws EnrollException.NotFound unknown conversation (404).
     */
    @Throws(IOException::class)
    suspend fun fetchSyncBatch(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        afterSequence: Long,
        limit: Int = 20,
    ): List<SyncBatchItem>

    /**
     * POST /api/e2ee/sync-history/ack with `{conversationId,
     * throughSequence}`. Companion-only prefix eviction of this device's
     * pending sync rows at or below [throughSequence]. Idempotent:
     * repeating the same or a lower prefix evicts nothing further.
     * Callers must ACK only through the highest locally durable
     * contiguous sequence, never through a gap.
     */
    @Throws(IOException::class)
    suspend fun ackSync(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        throughSequence: Long,
    ): SyncAckResult
}
