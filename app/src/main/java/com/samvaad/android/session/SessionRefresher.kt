package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.AuthApi
import com.samvaad.android.RefreshRejectedException
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Launch-time session restoration over a persisted refresh bundle.
 *
 * - Refresh-on-launch always (never trust a persisted access token —
 *   none is persisted).
 * - Rotation is atomic from the caller's perspective: the new bundle is
 *   durably stored before success is reported; the old token never
 *   survives a successful refresh.
 * - Concurrent callers serialize on [mutex]: one network refresh, one
 *   shared result — a single stored refresh token can have only one
 *   winner server-side.
 * - Refresh rejection wipes the record and yields [SessionExpired];
 *   transport failures propagate without wiping anything.
 *
 * Knows HTTP only through [AuthApi]; knows crypto only through the
 * [SessionStore] seal. No UI, no enrollment, no background work.
 */
class SessionRefresher(
    private val authApi: AuthApi,
    private val store: SessionStore,
) {
    private val mutex = Mutex()

    /**
     * In-flight restore shared by concurrent callers. A bare mutex would
     * only serialize: followers would then re-refresh with the just-rotated
     * token, churning rotation and racing the stored record. Sharing one
     * result gives exactly one network refresh per burst.
     */
    private var inFlight: CompletableDeferred<RestoreOutcome>? = null

    /** Outcome of a launch-time restore attempt. */
    sealed interface RestoreOutcome {
        /** Live in-memory session; [serverAddress] for subsequent calls. */
        data class Authenticated(val session: AuthSession, val serverAddress: String) : RestoreOutcome

        /** No record, or record unusable: show the login form. */
        data object NoStoredSession : RestoreOutcome

        /** Record existed but cannot yield a session: login with the
         * expired-session message. The record was already wiped unless
         * the wrapping key itself is missing. */
        data object SessionExpired : RestoreOutcome

        /** Network (or undecipherable-transport) failure: nothing wiped,
         * caller shows the unreachable message with retry. */
        data object Unreachable : RestoreOutcome
    }

    /** Restore a live session from the persisted bundle, if any. */
    suspend fun restoreSession(): RestoreOutcome {
        val mine: CompletableDeferred<RestoreOutcome>
        val owner: Boolean
        mutex.withLock {
            val existing = inFlight
            if (existing == null) {
                mine = CompletableDeferred()
                inFlight = mine
                owner = true
            } else {
                mine = existing
                owner = false
            }
        }
        if (!owner) return mine.await()
        return try {
            val outcome = doRestore()
            mine.complete(outcome)
            outcome
        } catch (e: Throwable) {
            mine.completeExceptionally(e)
            throw e
        } finally {
            mutex.withLock {
                if (inFlight === mine) inFlight = null
            }
        }
    }

    private suspend fun doRestore(): RestoreOutcome {
        val record = try {
            store.load() ?: return RestoreOutcome.NoStoredSession
        } catch (e: SessionStoreException) {
            // Corrupt record is provably useless: wipe it (session store
            // only — crypto/device state untouched). A missing wrapping
            // key proves nothing about the file: leave it alone.
            if (!e.keyMissing) {
                store.clear()
            }
            return RestoreOutcome.SessionExpired
        }
        if (record.refreshExpiresAtEpochMillis <= System.currentTimeMillis()) {
            // Local fast-path only; the server remains authoritative and a
            // skewed clock can only cost one extra login, never access.
            store.clear()
            return RestoreOutcome.SessionExpired
        }
        val refreshed = try {
            authApi.refresh(record.serverAddress, record.refreshToken)
        } catch (e: RefreshRejectedException) {
            store.clear()
            return RestoreOutcome.SessionExpired
        } catch (e: IOException) {
            return RestoreOutcome.Unreachable
        }
        val rotated = PersistedSession(
            serverAddress = record.serverAddress,
            identifier = record.identifier,
            refreshToken = refreshed.refreshToken,
            sessionId = refreshed.sessionId,
            refreshExpiresAtEpochMillis = System.currentTimeMillis() +
                TimeUnit.DAYS.toMillis(REFRESH_VALIDITY_DAYS),
        )
        try {
            store.save(rotated)
        } catch (e: SessionStoreException) {
            // The old token is already server-invalidated by the rotation,
            // so the on-disk record is dead either way: wipe it and fail
            // closed instead of reporting a restorable session.
            store.clear()
            return RestoreOutcome.SessionExpired
        }
        return RestoreOutcome.Authenticated(
            AuthSession(
                identifier = record.identifier,
                accessToken = refreshed.accessToken,
                refreshToken = refreshed.refreshToken,
                sessionId = refreshed.sessionId,
            ),
            record.serverAddress,
        )
    }

    /**
     * Persist the bundle from a fresh login BEFORE the UI treats the state
     * as durable. @throws SessionStoreException when durability is
     * unavailable — callers proceed with the live session anyway (pre-slice
     * behavior) and make no durability claim.
     */
    suspend fun persistLogin(serverAddress: String, session: AuthSession) {
        store.save(
            PersistedSession(
                serverAddress = serverAddress,
                identifier = session.identifier,
                refreshToken = session.refreshToken,
                sessionId = session.sessionId,
                refreshExpiresAtEpochMillis = System.currentTimeMillis() +
                    TimeUnit.DAYS.toMillis(REFRESH_VALIDITY_DAYS),
            )
        )
    }

    /**
     * Best-effort server revocation, then unconditional local wipe. Never
     * touches device metadata, vault records, or the wrapping key.
     */
    suspend fun logout(serverAddress: String, session: AuthSession) {
        try {
            authApi.logout(serverAddress, session.accessToken)
        } catch (_: IOException) {
            // Server revocation is idempotent; local wipe is what matters.
        } finally {
            store.clear()
        }
    }

    companion object {
        /**
         * Local mirror of the server's 30-day rolling refresh validity,
         * used only for the happy-path fast check. Rejection is always
         * authoritative; a wrong constant here costs at most one login.
         */
        const val REFRESH_VALIDITY_DAYS = 30L
    }
}
