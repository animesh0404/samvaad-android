package com.samvaad.android.crypto

/**
 * Fail-closed session-establishment errors. Messages carry no key
 * material, no plaintext, and no ciphertext — only the structural reason
 * for refusal.
 *
 * None of these conditions may trigger regeneration of the local identity
 * or fabrication of a SessionRecord.
 */
sealed class SessionCryptoException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    /** Bundle bytes do not parse as libsignal key material. */
    class InvalidBundle(cause: Throwable? = null) :
        SessionCryptoException("recipient bundle failed validation", cause)

    /** Server row predates Kyber support (null Kyber triple). */
    class KyberUnsupported :
        SessionCryptoException("recipient device does not support PQXDH")

    /** Signed-prekey or Kyber signature does not verify under the
     * recipient identity key. */
    class InvalidSignature(which: String) :
        SessionCryptoException("recipient $which signature invalid")

    /** Remote identity is distrusted (TOFU pin mismatch). */
    class UntrustedIdentity(cause: Throwable? = null) :
        SessionCryptoException("recipient identity not trusted", cause)

    /** `SessionBuilder.process` failed without a more specific cause. */
    class EstablishmentFailed(cause: Throwable? = null) :
        SessionCryptoException("session establishment failed", cause)

    /** Stored SessionRecord bytes do not restore, or the restored
     * session has no sender chain. */
    class SessionCorrupt(cause: Throwable? = null) :
        SessionCryptoException("stored session failed validation", cause)

    /**
     * The exact ciphertext was already processed against the persisted
     * session state (experimentally proven: `DuplicateMessageException`
     * with no store mutation). Not a failure — the caller must ACK
     * without delivering plaintext again.
     */
    class DuplicateMessage(cause: Throwable? = null) :
        SessionCryptoException("ciphertext already processed", cause)
}
