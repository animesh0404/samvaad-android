package com.samvaad.android.session

/**
 * Outbound session-establishment outcomes (slice: session establishment).
 *
 * Fixed safe results only — no server bodies, no stack traces, no key
 * material. [Established] is the only success; every other value is a
 * terminal classification for this attempt (callers decide retry policy;
 * only [TransportRetryable] is safe to retry unchanged).
 */
sealed interface SessionEstablishResult {
    /**
     * A durable session exists and is reusable. [reused] distinguishes a
     * reused valid session (no claim, no `process`) from a fresh
     * establishment.
     */
    data class Established(val entry: SignalSessionEntry, val reused: Boolean) :
        SessionEstablishResult

    /** Directory returned `200 []`: user exists but has no ACTIVE devices. */
    data object NoDevices : SessionEstablishResult

    /** Requested `deviceId` is not among the user's ACTIVE devices. */
    data class DeviceNotFound(val deviceId: String) : SessionEstablishResult

    /** Target row is not ACTIVE (defensive: the directory hides these). */
    data object DeviceNotActive : SessionEstablishResult

    /** Caller is not a friend of the target user (directory/claim 403). */
    data object NotFriends : SessionEstablishResult

    /** Unknown user (directory 404). Re-discover, do not retry blindly. */
    data object TargetNotFound : SessionEstablishResult

    /** 401: caller must re-login. */
    data object Unauthorized : SessionEstablishResult

    /** Same-`requestId` claim race survived the single internal retry. */
    data object ClaimConflict : SessionEstablishResult

    /** Recipient row predates Kyber support; PQXDH impossible. */
    data object KyberUnsupported : SessionEstablishResult

    /** Bundle failed parsing/signature validation. */
    data class InvalidBundle(val reason: String) : SessionEstablishResult

    /** Remote identity differs from the pinned metadata value. */
    data object IdentityMismatch : SessionEstablishResult

    /**
     * Metadata exists but the session blob is missing/corrupt/unready, or
     * persistence failed. Never auto-regenerates identity or session.
     */
    data class SessionUnavailable(val reason: String) : SessionEstablishResult

    /** No adopted local device, or local crypto is unrecoverable. */
    data object CryptoUnavailable : SessionEstablishResult

    /** Transport failure or malformed server response: retry is safe.
     * Nothing was cached or persisted on this attempt, so any retry
     * claims fresh — but a malformed claim response may hide an
     * already-consumed OTPK, which the fresh-claim rule absorbs. */
    data object TransportRetryable : SessionEstablishResult

    /** Any other server rejection (400/409-limit/recovery/unknown). */
    data class Rejected(val reason: String) : SessionEstablishResult
}
