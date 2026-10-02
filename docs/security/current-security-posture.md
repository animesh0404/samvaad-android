# Current Security Posture

This document describes the Android client's actual security posture, not the server's security properties.

## Implemented now

The Android application (bootstrap + Slice 1 entry screen + Slice 2
authentication boundary + Slice 4 first-device bootstrap + Slice 5
durable session) has:

- network transport for login/refresh/logout plus E2EE device
  enrollment/prekey calls;
- no WebSocket/realtime integration;
- refresh-token session bundle sealed under the existing Keystore
  wrapping key in a separate no-backup namespace (server address,
  identifier, refresh token, session ID, refresh expiry); access tokens
  memory-only; passwords never persisted;
- no stored credentials;
- durable E2EE private material, sealed per-record under a non-exportable
  Keystore AES-256-GCM wrapping key in `getNoBackupFilesDir()` (never
  plaintext, never logged, Keystore holds the wrapping key only);
- non-secret enrollment metadata (attempt marker, adopted-device hints,
  ID high-water marks) in a separate `getNoBackupFilesDir()` file —
  never private bytes, codes, or tokens; never treated as authority;
- recovery codes shown transiently exactly once, never persisted/logged;
- no database/DataStore/preferences or other application persistence;
- no message content handling.

The Slice 1 entry screen held the typed values only in in-memory Compose
UI state. Slice 2 keeps that posture and adds the login call below.

Slice 2 transmits the identifier and password over HTTPS to the
configured server address only and clears the password from UI state on
success. Slice 5 persists the refresh bundle at login and rotates it on
every refresh; logout revokes best-effort and always wipes the local
session record while leaving device/crypto state intact. The
authenticated UI receives the identifier string only, never the session
object or tokens. Passwords, tokens, and session credentials
are never logged, never rendered, and never persisted outside the sealed
session record.

In-memory access/refresh tokens and the sessionId are therefore runtime
secrets: the fixed safe UI messages must never carry server text, HTTP
internals, or credential material.

## Current security rules for future slices

- Never log passwords, access tokens, refresh tokens, recovery codes, or private cryptographic material.
- Do not persist credentials in plaintext.
- Keep authentication/session state separate from cryptographic device state.
- The server assigns PRIMARY/COMPANION roles; Android must never self-declare a role.
- Private keys are generated and retained on the client; private keys are never sent to the server.
- Enrollment uncertain outcomes reconcile against server device state and never regenerate identity merely because a request failed.
- Recovery codes remain display-once transients.
- Outbound session establishment verifies signed-prekey and Kyber signatures locally, pins the remote identity, and fails closed on identity/session-state mismatch.
- A claimed OTPK is never reused after a failed post-claim establishment attempt.

## Current template caveat

The generated manifest references Android backup-rule resources that
remain template placeholders. Sensitive crypto state is now stored, but
exclusively in `getNoBackupFilesDir()` (vault records, enrollment
metadata) plus the Keystore-held wrapping key — locations the backup
transports exclude by construction. Backup-rule/release hardening for
any future backed-up data remains deferred; revisit before introducing
persistent credentials, message history, or any backup-eligible store.

## Deferred security architecture

Not yet implemented/locked:

- user-facing identity verification/fingerprint and trust-state workflow;
- OTPK replenishment trigger and Kyber rotation;
- wrapping-key rotation and lifecycle policy;
- encrypted backup/restore;
- inbound message/decryption security boundaries;
- mailbox/history/cursor security model;
- push-notification security/privacy design;
- final server retention/liveness policies;
- Primary-to-Companion history-sync security/protocol design;
- AGPL-3.0-only libsignal distribution decision.
