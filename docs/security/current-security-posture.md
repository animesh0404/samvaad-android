# Current Security Posture

This document describes the Android client's actual security posture, not the server's security properties.

## Implemented now

The Android application through Slice 11 has:

- HTTPS-only login/refresh/logout plus existing E2EE device, directory/claim, message-submission, mailbox-fetch/ack, history, and cursor calls;
- no WebSocket/realtime integration, background mailbox polling, or push delivery;
- refresh-token session bundle sealed under the existing Keystore wrapping key in a separate no-backup namespace; access tokens memory-only; passwords never persisted;
- durable E2EE private material sealed per record under a non-exportable Keystore AES-256-GCM wrapping key in `getNoBackupFilesDir()`; Keystore holds only the wrapping key;
- non-secret enrollment/device/session metadata in separate no-backup files; private bytes, recovery codes, message plaintext, ciphertext, and tokens are not stored in metadata;
- recovery codes shown transiently during first bootstrap and never persisted/logged;
- Room-backed durable message/conversation state under `getNoBackupFilesDir()/message-state/messages.db`;
- message plaintext stored only as sealed BLOBs protected by the existing Keystore-backed wrapping key; Room does not contain plaintext message bytes;
- opaque message ciphertext may be retained alongside sealed plaintext for reconciliation, but is not treated as a durable decryptability guarantee;
- outbound remote signed-prekey/Kyber signature verification and remote identity pinning;
- outbound post-encrypt `SessionRecord` persistence before message submission;
- inbound explicit PREKEY_INIT/RATCHET parsing and real libsignal 0.86.5 decryption;
- inbound remote identity pinning/fail-closed mismatch handling;
- inbound post-decrypt `SessionRecord` persistence and sealed plaintext durability before per-message mailbox acknowledgment;
- `DuplicateMessageException` handling as the only duplicate-processing proof that permits acknowledgment without plaintext redelivery, with durable local message existence checked before accepting that proof;
- ordinary decrypt/persistence failures remain unacknowledged for redelivery;
- unknown inbound `senderDeviceId` entries do not trigger discovery, OTPK claims, or session creation;
- shared per-remote-device locking prevents concurrent outbound/inbound mutation of one Signal SessionRecord;
- bounded, headless history/cursor reconciliation with contiguous-only cursor advancement;
- server-defined Companion approval and recovery UX with manual device-state re-query and no background polling;
- recovery codes held only transiently during recovery actions and cleared after attempts/leaving the recovery surface;
- recovery bind requests that carry no private key material;
- explicit qualification of handle-less bound-device state: server session/device binding may succeed while local messaging remains unavailable until local crypto material exists;
- fail-closed messaging guards for adopted devices without local crypto handles;
- no message content is logged or stored in the Room database in plaintext;
- user-facing conversation/history presentation reads only sealed message-content BLOBs from Room and opens them in memory;
- manual Sync is the only Slice 11 reconciliation trigger; there is still no background polling, push, or realtime delivery;
- recipient selection requires an explicit friend username and explicit recipient-device choice before sending;
- UI duplicate-send protection does not replace the durable MessageSender recovery/idempotency invariants.

### Durable message-state invariant

Signal ciphertext alone is not sufficient to serve as durable Primary conversation history. After the Signal ratchet advances, old ciphertext cannot be assumed to remain independently decryptable indefinitely. The Android Primary therefore persists decrypted message content in sealed form for durable local message state/history.

The storage boundary is:

- **Room:** conversation/message metadata plus opaque ciphertext and sealed message-content BLOBs;
- **Keystore-backed crypto vault:** private keys and Signal `SessionRecord` blobs;
- **Keystore:** non-exportable wrapping key material.

Room itself is not an encrypted database. Message content confidentiality at rest comes from `MessageContentSealer` and the Keystore-held wrapping key.

### Crash and delivery invariants

Room and Keystore are separate durability systems; no two-phase commit is assumed.

Outbound recovery:

`PENDING_SEAL → SEALED → SENT`

- `SEALED` rows retain the exact ciphertext/request identity required for safe replay.
- `PENDING_SEAL` rows can be rebuilt from sealed plaintext with a fresh logical message/request identity.
- An accepted response that is lost can converge by replaying the same sealed submission identity.

Inbound recovery:

`DECRYPTED → SEALED → ACKED`

- plaintext is sealed before the local message state is durable;
- the mutated Signal SessionRecord is sealed before ACK;
- ACK failure leaves durable state eligible for mailbox redelivery;
- duplicate delivery is acknowledged only when durable local message state proves the message already exists;
- cursor failure does not undo durable message state or mailbox ACK; a later reconciliation can advance the cursor.

### History and cursor boundary

Server history is used as a bounded reconciliation/replay source. It is not treated as the permanent plaintext archive.

The local synchronization cursor is advanced only through the highest contiguous locally durable sequence. A gap prevents advancement beyond that gap.

The reconciliation sweep is bounded and deterministic. It is not a scheduler, background worker, push mechanism, or realtime subsystem.

## OTPK and Kyber lifecycle boundaries

After a successful PREKEY decrypt, libsignal consumes the corresponding OTPK in its inbound store, but the historical OTPK record remains in the Android vault. Durable OTPK cleanup/reconciliation belongs to the future replenishment/inventory lifecycle; the server-side atomic claim is authoritative and duplicate session state prevents replay of the already-processed ciphertext.

Kyber last-resort material remains durable by design. The adapter's process-scoped `markKyberPreKeyUsed` tracking matches libsignal's in-memory reference semantics and preserves crash-before-session-seal recovery. Persisting this used-set separately would interfere with the required redelivery/recovery path.

## Current security rules for future slices

- Never log passwords, access tokens, refresh tokens, recovery codes, plaintext, ciphertext, or private cryptographic material.
- Do not persist credentials or message content in plaintext.
- Keep authentication/session state separate from cryptographic device state and message-state persistence.
- The server assigns PRIMARY/COMPANION roles; Android must never self-declare a role.
- Private keys are generated and retained on the client; private keys are never sent to the server.
- Enrollment uncertain outcomes reconcile against server device state and never regenerate identity merely because a request failed.
- Recovery codes remain display-once/transient values and are never persisted.
- Approval is only exposed from an ACTIVE-bound device; Android does not self-authorize approval.
- Pending denial is represented by server revocation and converges through authoritative device listing.
- Recovery bind adopts an existing server device without accepting private key material; recover-enroll is the path that creates new local private material.
- Outbound session establishment verifies signed-prekey and Kyber signatures locally, pins the remote identity, and fails closed on identity/session-state mismatch.
- A claimed OTPK is never reused after a failed post-claim establishment attempt.
- Inbound processing must persist the mutated Signal SessionRecord and sealed message content before acknowledging the mailbox entry.
- Only a proven duplicate path may authorize acknowledgment without another plaintext delivery; ordinary decrypt failures remain unacknowledged.
- Outbound and inbound operations for the same remote device must share the same session mutation lock.
- Cursor advancement must remain contiguous-only and must never manufacture completion across a sequence gap.

## Current template caveat

The generated manifest references Android backup-rule resources that remain template placeholders. Sensitive crypto state and message-state files are stored under `getNoBackupFilesDir()` plus the Keystore-held wrapping key. Backup-rule/release hardening for any future backed-up data remains deferred; revisit before introducing any backup/export feature.

## Deferred security architecture

Not yet implemented/locked:

- user-facing identity verification/fingerprint and trust-state workflow;
- OTPK replenishment and Kyber rotation;
- wrapping-key rotation/lifecycle policy;
- encrypted backup/restore;
- user-facing message/history access-control and deletion/retention policy;
- push-notification security/privacy design;
- final server retention/liveness policies;
- Primary-to-Companion history-sync security/protocol design;
- recovery-code rotation;
- AGPL-3.0-only libsignal distribution decision.
