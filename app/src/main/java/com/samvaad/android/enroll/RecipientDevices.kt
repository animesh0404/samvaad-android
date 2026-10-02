package com.samvaad.android.enroll

/**
 * Device-discovery DTOs (slice: outbound session establishment).
 *
 * Wire mirror of the server contract at baseline `164463da`:
 * `GET /api/e2ee/users/{username}/devices` returns a bare JSON array of
 * recipient devices (ACTIVE only); `POST
 * /api/e2ee/devices/{deviceId}/one-time-prekeys/claim` returns the same
 * bundle plus an optional consumed one-time prekey (`null` = signed-prekey
 * fallback). All key fields are standard-Base64 public bytes; `org.json`
 * mapping lives in [HttpE2eeDeviceApi]. No libsignal types, no private
 * material.
 */

/** One ACTIVE recipient device from the directory (or claim) bundle. */
data class RecipientDeviceRecord(
    val deviceId: String,
    val registrationId: Int,
    val signalDeviceId: Int,
    val deviceIdentityPublicKey: String,
    val signedPrekeyId: Int,
    val signedPrekey: String,
    val signedPrekeySignature: String,
    val hasAvailableOneTimePrekey: Boolean,
    val deviceRole: String,
    /** Null triple = pre-Kyber row; cannot serve PQXDH bundles. */
    val kyberPrekeyId: Int?,
    val kyberPrekey: String?,
    val kyberPrekeySignature: String?,
)

/** One consumed EC one-time prekey from a claim response. */
data class ClaimedOneTimePrekey(
    val prekeyId: Int,
    val publicKey: String,
)

/**
 * Successful claim outcome: the recipient bundle plus the consumed
 * one-time prekey, or null [oneTimePrekey] on signed-prekey fallback.
 * Kyber material is present on fresh claims, replays, and fallbacks
 * alike (null only for pre-Kyber rows).
 */
data class ClaimedDeviceBundle(
    val deviceId: String,
    val registrationId: Int,
    val signalDeviceId: Int,
    val deviceIdentityPublicKey: String,
    val signedPrekeyId: Int,
    val signedPrekey: String,
    val signedPrekeySignature: String,
    val oneTimePrekey: ClaimedOneTimePrekey?,
    val deviceRole: String,
    val kyberPrekeyId: Int?,
    val kyberPrekey: String?,
    val kyberPrekeySignature: String?,
)
