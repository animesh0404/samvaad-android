# Current Security Posture

This document describes the Android client's actual security posture, not the server's security properties.

## Implemented now

The Android application (bootstrap + Slice 1 entry screen + Slice 2
authentication boundary + Slice 4 first-device bootstrap) has:

- network transport for login plus E2EE device enrollment/prekey calls;
- no WebSocket/realtime integration;
- no persisted access/refresh tokens or sessions (in-memory session only);
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
configured server address only, keeps access/refresh tokens and the
sessionId in memory only, and clears the password from UI state on
success. The authenticated UI receives the identifier string only, never
the session object or tokens. Passwords, tokens, and session credentials
are never logged, never rendered, and never persisted.

In-memory access/refresh tokens and the sessionId are therefore runtime
secrets: the fixed safe UI messages must never carry server text, HTTP
internals, or credential material.

## Required boundaries for future slices

When authentication is introduced:

- never log passwords, access tokens, refresh tokens, recovery codes, or private cryptographic material;
- do not persist credentials in plaintext;
- follow the server's existing session/authentication contracts;
- keep authentication/session state separate from cryptographic device state.

When E2EE/device enrollment is introduced:

- private keys must be generated and retained on the client;
- private keys must never be sent to the server;
- the server remains cryptographically blind;
- device role must be consumed from the server's read-only device representation; Android must not self-declare PRIMARY/COMPANION;
- enrollment must reuse (never regenerate) local identity on uncertain
  outcomes; ambiguous server state reconciles via identity-pubkey match
  or fails closed;
- recovery codes are display-once transients: never persisted, logged,
  or vaulted; crash-before-acknowledgment leaves an Active-unacked
  device, never re-issued codes.

When Primary history ownership is introduced:

- durable local conversation history becomes security-sensitive application data;
- backup/restore semantics must be designed before enabling Android backup for such data;
- the future Companion history-sync protocol must remain E2EE.

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

- secure cryptographic key persistence format;
- encrypted backup/restore;
- final history-sync protocol;
- push-notification security/privacy design;
- final server retention/liveness policies.
