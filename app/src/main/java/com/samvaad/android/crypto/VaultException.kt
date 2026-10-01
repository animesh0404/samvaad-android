package com.samvaad.android.crypto

/**
 * Fail-closed vault errors. Messages carry no key material, no plaintext,
 * and no ciphertext — only the structural reason for refusal.
 *
 * None of these conditions may trigger regeneration of crypto material or
 * creation of a replacement wrapping key.
 */
sealed class VaultException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    /** No stored envelope for this handle. */
    class RecordMissing :
        VaultException("no stored record")

    /** Wrapping key absent while encrypted data exists. Fail closed. */
    class WrappingKeyMissing :
        VaultException("wrapping key unavailable")

    /** GCM authentication failure, truncation, or unparseable envelope. */
    class CorruptEnvelope :
        VaultException("stored record failed integrity validation", null)

    /** Envelope version this implementation does not understand. */
    class UnknownVersion(val version: Int) :
        VaultException("unsupported record version")

    /** Envelope kind/UUID does not match the requested handle. */
    class HandleMismatch :
        VaultException("stored record does not match requested handle")

    /** Envelope could not be written to or read from disk. Fail closed. */
    class StorageFailure(cause: Throwable? = null) :
        VaultException("local crypto storage unavailable", cause)
}
