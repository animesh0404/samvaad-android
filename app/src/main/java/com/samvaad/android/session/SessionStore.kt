package com.samvaad.android.session

import java.io.IOException

/**
 * Durable refresh-session record. Refresh token only — the access token
 * stays memory-only (24h validity + refresh-on-launch make persisting it
 * pointless), and the password is never persisted anywhere.
 *
 * Server address is part of the record: calls have no base URL without it,
 * and it must never be hardcoded or inferred.
 */
data class PersistedSession(
    val schemaVersion: Int = SessionStore.SCHEMA_VERSION,
    val serverAddress: String,
    val identifier: String,
    val refreshToken: String,
    val sessionId: String,
    val refreshExpiresAtEpochMillis: Long,
)

/**
 * Session-store failure. Fail closed: callers treat the session as
 * unavailable and never attempt repair. [keyMissing] distinguishes a
 * missing Keystore key (leave the file alone — nothing is proven about
 * it) from corruption/rejection (the record is provably useless).
 */
class SessionStoreException(
    message: String,
    cause: Throwable? = null,
    val keyMissing: Boolean = false,
) : IOException(message, cause)

/** Durable refresh-session custody. Knows nothing about HTTP or UI. */
interface SessionStore {
    /** Atomically replace the stored record. @throws SessionStoreException */
    fun save(record: PersistedSession)

    /**
     * @return the record, or null when absent.
     * @throws SessionStoreException on corruption, schema mismatch, or
     * missing wrapping key.
     */
    fun load(): PersistedSession?

    /** Delete the record. Best effort; never throws. */
    fun clear()

    companion object {
        const val SCHEMA_VERSION = 1
    }
}
