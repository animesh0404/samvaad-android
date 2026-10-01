package com.samvaad.android.crypto

/**
 * Fail-closed libsignal recovery error.
 *
 * Thrown when stored record bytes cannot be reconstructed into live
 * libsignal objects ([org.signal.libsignal.protocol.InvalidKeyException],
 * `InvalidMessageException`, or structural problems). Carries no key
 * material. Must never be interpreted as permission to generate new
 * crypto material.
 */
class CryptoRecoveryException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
