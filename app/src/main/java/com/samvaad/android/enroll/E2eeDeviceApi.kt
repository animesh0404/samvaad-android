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

    /** 401 or missing/invalid auth. Caller should re-login. */
    class Unauthorized : EnrollException("unauthorized")

    /** 400 validation/server rejection of the request shape. */
    class BadRequest : EnrollException("bad request")

    /** 403 with reason `E2EE_RECOVERY_REQUIRED` (or other 403). */
    class RecoveryRequired : EnrollException("recovery required")

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
}
