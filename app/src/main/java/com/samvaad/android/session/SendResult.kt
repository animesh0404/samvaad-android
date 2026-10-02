package com.samvaad.android.session

/**
 * Outbound message-send outcomes (slice: message submission).
 *
 * Fixed safe results only — no server bodies, no stack traces, no key
 * material, no plaintext. [Sent] is the only success. A [Failed] result
 * carries a live-retry handle ONLY for transport failures that happened
 * after the post-encrypt session was sealed: the handle resubmits the
 * byte-identical request and never re-encrypts. All other failures carry
 * no retry — a new logical message (fresh requestId + fresh encryption)
 * is required instead.
 */
sealed interface SendResult {
    /** Ciphertext accepted by the server. [createdNew] is false on an
     * identical-requestId replay. */
    data class Sent(
        val entry: SignalSessionEntry,
        val messageId: String,
        val conversationId: String,
        val sequenceNumber: Long,
        val envelopeType: String,
        val createdNew: Boolean,
    ) : SendResult

    /** Terminal classification for this attempt; see [SendFailure]. */
    data class Failed(
        val kind: SendFailure,
        /** Resubmits the identical request; non-null only for [SendFailure.TransportRetryable]. */
        val retry: (suspend () -> SendResult)? = null,
    ) : SendResult
}

sealed interface SendFailure {
    /** No adopted local device, or local crypto is unrecoverable. */
    data object CryptoUnavailable : SendFailure

    /** No session entry, or the sealed blob is missing/corrupt/unready. */
    data class SessionUnavailable(val reason: String) : SendFailure

    /** Sealed blob identity differs from the pinned metadata value. */
    data object IdentityMismatch : SendFailure

    /** Transport failure after persistence: retry the live handle with
     * identical bytes, never re-encrypt. */
    data object TransportRetryable : SendFailure

    /** 401: caller must re-login through the existing gate. The live
     * retry handle is NOT carried across re-authentication — start a
     * fresh send instead. */
    data object Unauthorized : SendFailure

    /** 403: sender spoof, inactive device, self/own-device recipient, or
     * non-friend. */
    data object Forbidden : SendFailure

    /** 404: recipient unknown or no longer ACTIVE. Re-discover. */
    data object NotFound : SendFailure

    /** 409: same requestId with different content. Fail closed — never
     * mint a new requestId automatically for the same bytes. */
    data object Conflict : SendFailure

    /** 400: server rejected the request shape. */
    data object BadRequest : SendFailure

    /** Any other server rejection, including malformed success bodies. */
    data class Rejected(val reason: String) : SendFailure
}
