package com.samvaad.android.enroll

/**
 * First-device enrollment DTOs (slice: bootstrap only).
 *
 * Pure data + `org.json` mapping lives in [HttpE2eeDeviceApi]. Field names
 * mirror the server contract (`POST /api/e2ee/devices`,
 * `PUT /api/e2ee/devices/{deviceId}/one-time-prekeys`,
 * `GET /api/e2ee/devices`) at baseline `164463da`. No libsignal types, no
 * private material: all key fields are standard-Base64 public bytes.
 */

/** Outgoing enrollment request. [clientPlatform] is always `ANDROID`. */
data class EnrollRequest(
    val registrationId: Int,
    val deviceIdentityPublicKey: String,
    val signedPrekeyId: Int,
    val signedPrekey: String,
    val signedPrekeySignature: String,
    val kyberPrekeyId: Int,
    val kyberPrekey: String,
    val kyberPrekeySignature: String,
    val clientPlatform: String = "ANDROID",
    val clientName: String? = null,
    val clientVersion: String? = null,
)

/** Server-assigned device metadata we retain (non-secret cache, never authority). */
data class DeviceRecord(
    val deviceId: String,
    val registrationId: Int,
    val signalDeviceId: Int,
    val deviceIdentityPublicKey: String,
    val signedPrekeyId: Int,
    val deviceRole: String,
    val status: String,
    val availablePrekeys: Long,
    /**
     * Server kyber prekey id when the DTO carries it (bind/recovery
     * responses do; older shapes may omit it). Retained only so a
     * bind-adopted record stays faithful to server truth.
     */
    val kyberPrekeyId: Int? = null,
)

/** Successful enrollment outcome. [recoveryCodes] present only on first bootstrap. */
data class EnrollResult(
    val device: DeviceRecord,
    val enrollmentState: String,
    val recoveryCodes: List<String>?,
)

/** One OTPK entry for the provisioning batch. */
data class OneTimePrekeyUpload(
    val prekeyId: Int,
    val publicKey: String,
)

/** Owner device list used for reconciliation. */
data class DeviceList(
    val enrollmentState: String,
    val devices: List<DeviceRecord>,
)

/**
 * Session-to-device attach handshake (`POST
 * /api/e2ee/devices/{deviceId}/attach/begin` +
 * `.../attach/complete`). [AlreadyBound] is the idempotent success when
 * the session is already bound to this device — no cryptography involved.
 * [Challenge] carries the server's ephemeral X25519 public half for the
 * single proof round; the private half never leaves the server.
 */
sealed interface AttachBegin {
    data class AlreadyBound(val device: DeviceRecord) : AttachBegin
    data class Challenge(
        val challengeId: String,
        val serverEphemeralPublicKey: String,
        val expiresAt: String?,
    ) : AttachBegin
}
