package com.samvaad.android.enroll

import java.security.SecureRandom

/**
 * Local ID allocation for enrollment crypto material.
 *
 * The server defines no numeric ranges (`@NotNull` only), so this is a
 * documented local decision, not a server rule: positive integers,
 * independent namespaces per category (the server validates
 * signed/Kyber/OTPK IDs independently), OTPK IDs never reused within a
 * device. High-water marks live in [DeviceMetadataStore] so allocation
 * survives process death deterministically.
 */
class PrekeyIdAllocator(
    var signedHighWater: Int = 0,
    var kyberHighWater: Int = 0,
    var otpkHighWater: Int = 0,
) {
    /** Next signed-prekey ID (monotonic per device). */
    fun nextSignedPrekeyId(): Int = ++signedHighWater

    /** Next Kyber prekey ID (monotonic per device). */
    fun nextKyberPrekeyId(): Int = ++kyberHighWater

    /** Next block of [count] OTPK IDs (monotonic per device, never reused). */
    fun nextOneTimePrekeyIds(count: Int): List<Int> {
        require(count > 0) { "count must be positive" }
        return List(count) { ++otpkHighWater }
    }

    companion object {
        /**
         * One-time registration ID. Signal-plaintext range choice is local:
         * generated once, persisted in metadata, never regenerated while
         * the local identity lives.
         */
        fun newRegistrationId(random: SecureRandom = SecureRandom()): Int =
            1 + random.nextInt(REGISTRATION_ID_MAX)

        private const val REGISTRATION_ID_MAX = 16383
    }
}
