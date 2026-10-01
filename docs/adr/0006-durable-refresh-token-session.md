# ADR 0006: Durable Refresh-Token Session

- Status: Accepted
- Date: 2026-10-01

## Context

Slices 0–4 left `AuthSession` in memory only: every process death dropped
the user to a blank login form and stranded any bound session server-side
for up to 30 days, while crypto/device state already survived restarts
(ADR 0004/0005). The frozen server contract provides rotation
(`POST /api/auth/refresh`: new refresh token, same `sessionId`, binding
preserved; concurrent reuse has one winner) and idempotent single-session
revocation (`POST /api/auth/logout`). Access tokens are stateless JWTs
(24h); refresh tokens are opaque with 30-day rolling expiry; at most 5
active sessions per user.

## Decision

Persist only the refresh bundle (`serverAddress`, `identifier`,
`refreshToken`, `sessionId`, `refreshExpiresAt`); access tokens stay
memory-only. Storage reuses ADR 0004 exactly: same Keystore wrapping-key
alias, `RecordEnvelopeCodec` AES-GCM with a distinct kind byte, single
deterministic file under a separate `getNoBackupFilesDir()/session/`
namespace. No new dependencies, no Room/DataStore/SharedPreferences.

- Launch always refreshes (`SessionRefresher.restoreSession`); a single
  in-flight result is shared by concurrent callers (rotation admits only
  one winner). Rotation writes replace the record atomically; save
  failure after rotation fails closed (wipe + expired).
- Refresh rejection wipes the record and returns to login; transport
  failures wipe nothing. Corrupt records are wiped; a missing wrapping
  key leaves the file alone. Clocks are hints only — the server is
  authoritative.
- Logout revokes best-effort then wipes the session record
  unconditionally, including offline. It never touches device metadata,
  vault records, or the wrapping key, so a later login reconciles the
  existing device identity instead of duplicating it.
- One root `SessionGate` (no navigation framework): restoring indicator,
  then Home or login with a safe expired-session message. Fresh logins
  persist before Home is treated as durable; persistence failure still
  enters Home live and claims nothing.
- Generic 401-middleware is deferred; enrollment receives the restored
  live session unchanged, which also repairs the
  enroll-commit/OTPK-upload strand whenever the same logical session
  refreshes.

## Consequences

### Positive

- Restart/death/reboot preserve the authenticated user experience with
  no password re-entry; stranded bound sessions become resumable.
- Three independent lifetimes (session store, device metadata,
  vault/Keystore) match the server's own separation of session rows,
  device rows, and client-held keys.

### Negative

- A second login while a valid bundle exists creates a second server
  session against the 5-session cap; multi-account and background
  refresh remain future work.

## Scope

Session persistence, launch refresh, rotation, logout, and restart
recovery only. Companion/recovery/messaging flows, biometric lock,
push, backup, and release work stay out of scope, as does the
AGPL-3.0-only distribution decision (unchanged).
