# Current Security Posture

Baseline has no security-sensitive behavior. This document records the
absence honestly so later slices have a boundary to meet.

## Implemented: nothing sensitive

- No networking, no HTTP client, no WebSocket.
- No authentication, no tokens, no sessions, no credentials anywhere.
- No database, no DataStore/Preferences, no file writes.
- No E2EE keys, no keystore usage, no recovery codes.
- No logging of secrets (nothing to log).

## Boundaries for future slices (not implemented)

- Never persist or log passwords, tokens, private keys, or recovery codes in
  plaintext.
- When auth/enrollment arrive: hold secrets in memory only until a reviewed
  storage decision exists; follow the server’s `E2EE_RECOVERY_REQUIRED`
  routing and one-shot recovery-code display rules (see server checkpoint).
- The server stays cryptographically blind; the client must never send
  private keys to the server.
- Backup rules (`res/xml/backup_rules.xml`, `data_extraction_rules.xml`) are
  empty template placeholders — revisit before any credential/key storage.

## Deferred

- Encrypted backup/restore, keystore-backed storage, push notifications,
  rate-limit/error-code handling — all deferred with the features they
  belong to.
