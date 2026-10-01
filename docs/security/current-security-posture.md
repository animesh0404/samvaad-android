# Current Security Posture

This document describes the Android client's actual security posture, not the server's security properties.

## Implemented now

The Android application (bootstrap + Slice 1 entry screen + Slice 2
authentication boundary) has:

- no network transport beyond the single login HTTP call;
- no WebSocket/realtime integration;
- no persisted access/refresh tokens or sessions (in-memory session only);
- no stored credentials;
- no E2EE keys;
- no Android Keystore integration;
- no recovery codes;
- no database/DataStore/preferences or other application persistence;
- no file writes;
- no message content handling.

The Slice 1 entry screen held the typed values only in in-memory Compose
UI state. Slice 2 keeps that posture and adds the login call below.

Slice 2 transmits the identifier and password over HTTPS to the
configured server address only, keeps access/refresh tokens and the
sessionId in memory only, and clears the password from UI state on
success. Passwords, tokens, and session credentials are never logged,
never rendered, and never persisted.

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
- secure persistent cryptographic storage requires an explicit Android design before implementation.

When Primary history ownership is introduced:

- durable local conversation history becomes security-sensitive application data;
- backup/restore semantics must be designed before enabling Android backup for such data;
- the future Companion history-sync protocol must remain E2EE.

## Current template caveat

The generated manifest currently references Android backup-rule resources. They remain template placeholders and no sensitive application state is currently stored. Revisit backup configuration before introducing persistent credentials, keys, or message history.

## Deferred security architecture

Not yet implemented/locked:

- secure cryptographic key persistence format;
- encrypted backup/restore;
- final history-sync protocol;
- push-notification security/privacy design;
- final server retention/liveness policies.
