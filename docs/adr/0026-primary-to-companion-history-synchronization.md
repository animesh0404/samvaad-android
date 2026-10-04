# ADR 0026: Primary-to-Companion history synchronization protocol

## Status

ACCEPTED / IMPLEMENTED.

Server ADR 0025 remains authoritative for Primary-owned durable history and device roles. This ADR records the protocol frozen during Slice 12 design review and now implemented by the server and Android Primary/Companion paths.

## Context

Server ADR 0025 establishes the Android Primary as the authoritative source for durable conversation history and directs newly enrolled Companions to receive older history through an E2EE synchronization path. Slice 12 completed the protocol audit, threat-model challenge, completeness reviews, contract hardening, server foundation, server hardening, and Android implementation.

## Decision

Synchronize history as Companion-initiated manual pull over a minimal server-mediated opaque pending-set with prefix ACK, reusing existing per-device Signal sessions, with the Primary as the asserted authority (not the original senders), and no new crypto, Room migration, background, or push machinery.

## Protocol overview

The Companion pulls during manual Sync. The Primary, during its own manual Sync, uploads bounded idempotent batches for ACTIVE Companions. The server holds unacknowledged opaque per-item state and independent batch receipts; acknowledged prefixes are evicted and TTL is a backstop. The Companion decrypts through the existing inbound durable-state core, persists sealed content, advances durable contiguous position, and acknowledges the prefix.

There is no push, background polling, demand channel, or per-Companion job scheduler.

## Authority model

The Primary is authoritative for durable conversation history. The Companion and Primary roles are server-assigned; Android never self-declares a role. Revoked devices fail closed on every sync operation. If no ACTIVE Primary exists, synchronization is unavailable; no succession is invented.

The Primary's Signal identity authenticates the history transfer. It does not claim authorship of messages originally sent by another device.

## Initiation model

Companion-initiated pull is attached to the existing manual Sync entry point. Primary upload is blind and idempotent during its own manual sweep; sequence dedupe absorbs redundancy. Offline or stale peers leave visible pending state rather than creating a false completion signal.

## Primary export model

The Primary streams Room in server-sequence order, computes the highest-contiguous durable frontier, opens each sealed message BLOB transiently in memory, encrypts it into the existing Primary→Companion Signal session, and uploads bounded single-conversation batches.

No export store or export cursor is persisted on the Primary. Room plus server idempotency makes restart/retry safe.

## Companion pull model

The Companion fetches a sequence range, resolves the currently-authorized Primary session, decrypts and validates the envelope, seals the plaintext, persists the historical row, recomputes durable contiguity, and prefix-ACKs that contiguous position.

The historical message's original senderDeviceId and recipientDeviceId are preserved. Sync decryption uses the Primary session because the Primary is the transfer authority.

## Server pending-set model

Pending state is stored as opaque per-item rows keyed by Companion, conversation, and sequence, plus independent batch receipts keyed by globally unique syncBatchId. There is no queue-head entity, sync-cursor entity, or batch-container entity.

Pending items are evicted by prefix ACK and protected by the implemented seven-day lazy TTL. Receipts survive item eviction for idempotent replay/conflict detection within their TTL.

## Batch identity and conflicts

syncBatchId is a globally unique UUID per upload.

Identical canonical content under the same ID replays the stored receipt. Divergent content under the same ID returns 409.

The server rejects:
- same sequence with a different message;
- same message at a different sequence;
- same message with divergent ciphertext.

Upload is whole-batch atomic.

## Item identity and overlap

messageId is the stable message identity within the sync namespace. Server sequence is the ordering coordinate.

Overlapping batches are allowed and identical overlap converges through uniqueness/idempotency constraints. Prefix ACK is independent of batch identity.

## Encryption/envelope model

Each item is encrypted with the existing Primary→Companion Signal session. The encrypted payload carries:

- conversationId
- messageId
- sequenceNumber
- original senderDeviceId
- original recipientDeviceId
- original serverTimestamp
- plaintext message bytes
- per-conversation export frontier
- envelope version/type

The server sees only routing metadata and opaque ciphertext. It does not process plaintext or the encrypted frontier.

## Frontier semantics

The export frontier is the Primary's highest-contiguous durable Room sequence for the conversation at export time and is repeated inside each encrypted item.

The Companion stores lastSeenFrontier in the existing no-backup metadata-store pattern. Equality means complete as-of that frontier; a lower value indicates pending work; a regression is an explicit anomaly. The frontier is not an authenticated completeness proof and cannot recover history lost from Primary storage.

## Position and ACK model

The Companion's durable position is derived from Room contiguity. ACK throughSequence is always bounded by that durable contiguous position.

The existing mailbox/history delivery cursors are not reused for history sync. Server pending state and Android Room contiguity provide the sync progress boundary.

## Idempotency and crash behavior

syncBatchId governs upload receipt replay; messageId governs local ingest deduplication. messageRequestId remains scoped to ordinary message submission and is not reused.

Lost upload responses retry with the same batch ID. Lost fetch or ACK responses converge through range re-fetch, duplicate-absorbing ingest, and ACK retry. Room and Keystore remain separate durability systems; no distributed transaction is assumed.

## Revocation and multi-Companion behavior

Upload, fetch, and ACK are re-authorized against current server device state. Revoked devices fail closed. Each Companion has independent pending state, batch IDs, sessions, and per-device locks; one stalled Companion does not block another.

## Security invariants

- E2EE confidentiality is preserved.
- The server remains blind to plaintext and frontier contents.
- Primary authority is enforced by server role plus pinned Signal identity.
- Original message authorship metadata is preserved.
- Conflicting sequence/message data is rejected rather than substituted.
- Sync is at-least-once and idempotently convergent.
- Gaps and frontier regressions remain visible; no gap markers normalize missing history.
- No client-declared role is trusted.
- No plaintext server processing is introduced.

## Consequences

The protocol is implemented without a Room migration, new persistence architecture, new crypto primitive, push transport, background scheduler, or realtime channel.

The server has a bounded opaque pending-set with receipts; Android reuses existing Room, MessageContentSealer, InboxProcessor, SessionEstablisher, and SessionDeviceLocks seams.

## Deferred

Still deferred after implementation:

- final server retention/eviction policy beyond the sync pending TTL;
- Primary/Companion liveness and succession policy;
- backup/restore;
- push/realtime synchronization;
- Web Companion implementation and any web-specific UX;
- identity/fingerprint verification UI;
- OTPK replenishment and Kyber rotation;
- recovery-code rotation;
- AGPL-3.0-only libsignal distribution decision.
