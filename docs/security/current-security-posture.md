# Current Security Posture

This document describes the Android client's actual security posture, not the server's security properties.

## Implemented now

The Android application through Slice 8 has:

- HTTPS-only login/refresh/logout plus existing E2EE device, directory/claim, message-submission, mailbox-fetch, and mailbox-ack calls;
- no WebSocket/realtime integration, background mailbox polling, or push delivery;
- refresh-token session bundle sealed under the existing Keystore wrapping key in a separate no-backup namespace; access tokens memory-only; passwords never persisted;
- durable E2EE private material sealed per record under a non-exportable Keystore AES-256-GCM wrapping key in `getNoBackupFilesDir()`; Keystore holds only the wrapping key;
- non-secret enrollment/device/session metadata in separate no-backup files; private bytes, recovery codes, message plaintext, ciphertext, and tokens are not stored in metadata;
- recovery codes shown transiently during first bootstrap and never persisted/logged;
- no message/conversation database or durable plaintext/ciphertext message store;
- outbound remote signed-prekey/Kyber signature verification and remote identity pinning;
- outbound post-encrypt `SessionRecord` persistence before message submission;
- inbound explicit PREKEY_INIT/RATCHET parsing and real libsignal 0.86.5 decryption;
- inbound remote identity pinning/fail-closed mismatch handling;
- inbound post-decrypt `SessionRecord` persistence before per-message mailbox acknowledgment;
- `DuplicateMessageException` handling as the only duplicate-processing proof that permits acknowledgment without plaintext redelivery;
- ordinary decrypt/persistence failures remain unacknowledged for redelivery;
- unknown inbound `senderDeviceId` entries do not trigger discovery, OTPK claims, or session creation;
- shared per-remote-device locking prevents concurrent outbound/inbound mutation of one Signal SessionRecord;
- plaintext remains memory-only during inbound processing.

### Persistence and delivery invariant

Inbound processing deliberately follows:

`FETCH → DECRYPT → EXPORT → SEAL → ACK`

This prevents a mailbox ACK from declaring a message processed before the corresponding mutated Signal session state is durable.

The server mailbox remains the delivery/replay boundary for this slice. Fetching an entry does not mark it processed; acknowledgment deletes only the mailbox entry.

### OTPK and Kyber lifecycle boundaries

After a successful PREKEY decrypt, libsignal consumes the corresponding OTPK in its inbound store, but the historical OTPK record remains in the Android vault. Durable OTPK cleanup/reconciliation is deferred to the future replenishment/inventory lifecycle; the server-side atomic claim is authoritative and duplicate session state prevents replay of the already-processed ciphertext.

Kyber last-resort material remains durable by design. The adapter's process-scoped `markKyberPreKeyUsed` tracking matches libsignal's in-memory reference semantics and preserves crash-before-session-seal recovery. Persisting this used-set separately would interfere with the required redelivery/recovery path.

## Current security rules for future slices

- Never log passwords, access tokens, refresh tokens, recovery codes, plaintext, ciphertext, or private cryptographic material.
- Do not persist credentials, message plaintext, or message ciphertext in plaintext.
- Keep authentication/session state separate from cryptographic device state.
- The server assigns PRIMARY/COMPANION roles; Android must never self-declare a role.
- Private keys are generated and retained on the client; private keys are never sent to the server.
- Enrollment uncertain outcomes reconcile against server device state and never regenerate identity merely because a request failed.
- Recovery codes remain display-once transients.
- Outbound session establishment verifies signed-prekey and Kyber signatures locally, pins the remote identity, and fails closed on identity/session-state mismatch.
- A claimed OTPK is never reused after a failed post-claim establishment attempt.
- Inbound processing must persist the mutated Signal SessionRecord before acknowledging the mailbox entry.
- Only `DuplicateMessageException` may authorize acknowledgment without another plaintext delivery; all other decrypt failures remain unacknowledged.
- Outbound and inbound operations for the same remote device must share the same session mutation lock.

## Current template caveat

The generated manifest references Android backup-rule resources that remain template placeholders. Sensitive crypto state is now stored exclusively in `getNoBackupFilesDir()` plus the Keystore-held wrapping key. Backup-rule/release hardening for any future backed-up data remains deferred; revisit before introducing persistent message/history state or other backup-eligible stores.

## Deferred security architecture

Not yet implemented/locked:

- user-facing identity verification/fingerprint and trust-state workflow;
- OTPK replenishment and Kyber rotation;
- wrapping-key rotation/lifecycle policy;
- encrypted backup/restore;
- local message/history persistence and its threat model;
- mailbox/history/cursor reconciliation beyond the current per-message ACK boundary;
- push-notification security/privacy design;
- final server retention/liveness policies;
- Primary-to-Companion history-sync security/protocol design;
- AGPL-3.0-only libsignal distribution decision.
