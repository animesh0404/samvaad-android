# ADR 0009 — Durable Message State and History/Cursor Reconciliation

- Status: Accepted
- Date: 2026-10-03

## Context

Slices 7 and 8 established Android outbound encrypted message submission and inbound mailbox decryption, but inbound plaintext was previously memory-only. The Android Primary now needs durable local message state that survives process death and can reconcile safely with the server's existing mailbox, ciphertext history, and per-conversation synchronization cursors.

The storage boundary crosses two durability systems:

- Android Keystore-backed crypto storage for private keys and Signal `SessionRecord` blobs;
- a relational local store for message/conversation facts and durable message content.

These stores cannot participate in one Android transaction. The design therefore must not assume Room and Keystore are atomically committed together.

A second constraint is cryptographic: Signal ciphertext alone is not a durable history representation. Once a ratchet advances, an old ciphertext cannot be assumed to remain independently decryptable forever. Durable Primary history therefore requires locally persisted decrypted content protected at rest.

## Decision

### 1. Room is the durable message-state boundary

Android uses Room for relational message/conversation facts.

The Slice 9 database is stored under:

`getNoBackupFilesDir()/message-state/messages.db`

Room stores:

- conversation identity and local cursor state;
- local and server message identifiers;
- conversation sequence numbers;
- direction and device identifiers;
- envelope type;
- opaque ciphertext where retained for reconciliation;
- sealed plaintext BLOBs;
- send/ACK state;
- request IDs and server timestamps.

Room never stores private keys or Signal `SessionRecord` material.

Schema v1 is a fresh-install boundary. No destructive fallback is used.

### 2. Existing Keystore vault remains the crypto boundary

Android continues to store private key records and Signal `SessionRecord` blobs in the existing Keystore-backed crypto vault.

`MessageContentSealer` reuses the existing Keystore wrapping key and record-envelope mechanism with a dedicated message-content kind. No second message-specific key hierarchy is introduced.

Room is not treated as an encrypted database. Message-content confidentiality at rest comes from the sealed content BLOB and the Keystore-held wrapping key.

### 3. Durable state machines replace cross-store transactions

Room and Keystore are separate durability systems. Android does not implement two-phase commit between them.

Outbound recovery follows:

`PENDING_SEAL → SEALED → SENT`

- `PENDING_SEAL` means sealed message content is available to rebuild a safe fresh logical send attempt.
- `SEALED` retains the exact ciphertext/request identity needed for replay.
- acceptance records the server-assigned message ID, sequence, and timestamp and transitions the local row to sent.

Inbound recovery follows:

`DECRYPTED → SEALED → ACKED`

The decrypted content is sealed before the durable message row is accepted. The mutated Signal `SessionRecord` is sealed before mailbox ACK.

If ACK fails, durable local state remains and mailbox redelivery converges through duplicate handling. If cursor advancement fails, durable message state and ACK remain intact and a later reconciliation can retry the cursor.

### 4. Local and server identifiers remain distinct

The local `messageId` is distinct from the server-assigned `serverMessageId`.

The local `messageId` is the durable Room identity used for idempotent local state and sealed-content AAD. The server message ID/sequence/timestamp are recorded after server acceptance for reconciliation with server history.

A server response is therefore never treated as proof that the local primary key and server message identity are the same identifier.

### 5. Server history and synchronization cursors are reconciliation inputs

Android consumes the existing server contracts:

- `GET /api/e2ee/conversations/{conversationId}/messages?afterSequence=&limit=`
- `GET /api/e2ee/sync?conversationId=`
- `PUT /api/e2ee/sync`

Server history is a bounded replay/reconciliation source, not a replacement for local durable Primary message state.

The local cursor is advanced only through the highest contiguous locally durable sequence. Gaps prevent advancement past the gap. Cursor writes remain bounded by server state.

### 6. Reconciliation is bounded and idempotent

`ReconciliationSweep` runs four bounded branches in order:

1. recover outbox;
2. reconcile mailbox/ACK state;
3. ingest known-conversation history;
4. advance contiguous synchronization cursors.

It is deterministic and safe to re-enter after crashes. It has no scheduler, background worker, push dependency, or realtime dependency.

### 7. Session mutation remains serialized

Outbound, inbound, and reconciliation paths share `SessionDeviceLocks` for the same remote device. Signal `SessionRecord` mutation is therefore serialized across directions.

Server ACK operations occur outside the session mutation lock because they do not mutate the local Signal session and are idempotent/convergent.

## Consequences

- Android now has durable local message state suitable for process-death recovery.
- Inbound plaintext is no longer memory-only; it is protected at rest in sealed form.
- Old ciphertext is retained only as an opaque reconciliation aid and is not assumed to remain decryptable indefinitely.
- Room adds a relational persistence dependency and a schema boundary to the Android client.
- Crash recovery is explicit and state-machine driven rather than based on a false cross-store atomicity guarantee.
- Server history/cursors can reconcile local state without becoming the long-term plaintext archive.
- User-facing chat/history presentation, Companion synchronization, server retention/eviction, backup/restore, realtime delivery, and scheduling remain separate concerns.
- The AGPL-3.0-only libsignal distribution decision remains outstanding.

## Scope

This ADR covers Android local durable message state, sealed message content, outbound/inbound crash recovery, server history/cursor reconciliation, and shared SessionRecord mutation locking.

It does not define server retention/eviction, Primary succession/liveness, Primary-to-Companion history-sync protocol, push/realtime delivery, backup/restore, or user-facing chat UX.
