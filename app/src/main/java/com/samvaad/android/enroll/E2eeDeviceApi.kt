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
}
