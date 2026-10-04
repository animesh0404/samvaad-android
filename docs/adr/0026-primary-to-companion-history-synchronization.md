# ADR 0026: Primary-to-Companion history synchronization protocol

## Status

PROPOSED. Not accepted, not implemented.

Server ADR 0025 remains authoritative for Primary-owned durable history and device roles. This ADR proposes (it does not define or redefine) the wire protocol, authorization composition, and client behavior for synchronizing Primary history to Companion devices. The server contract it describes does not exist in code. Nothing here may be read as already implemented.

## Context

Server ADR 0025 establishes the Android Primary as the authoritative source for durable conversation history and directs newly enrolled Companions to receive older history through an E2EE synchronization path, but explicitly leaves the history-sync wire protocol open. The current server exposes device enrollment/approval/recovery, per-device ciphertext transport (submit, mailbox, history replay, cursors), and role enforcement — and nothing for same-user device-to-device history transfer; same-user message submission is deliberately forbidden. Slice 12 passed an architecture audit, a threat-model challenge, two completeness reviews, and a contract-hardening review. This ADR freezes the resulting candidate protocol for review.

## Problem

A newly enrolled Companion has no authorized path to the Primary's durable history, and no defined wire format, cursor, idempotency, authorization composition, or crash model exists for transferring it without weakening E2EE, turning the server into a backup, or inventing device succession.

## Decision

Synchronize history as Companion-initiated manual pull over a minimal server-mediated opaque pending-set with prefix ACK, reusing existing per-device Signal sessions, with the Primary as the asserted authority (not the original senders), and no new crypto, no Room migration, and no background or push machinery.

## Protocol overview

The Companion pulls, during manual Sync, sequence ranges it has not yet persisted. The Primary, during its own manual sweep, opportunistically uploads idempotent batches for ACTIVE Companions. The server holds only unacknowledged opaque batches and evicts on prefix ACK (TTL backstop). The Companion ingests through the existing inbound durable-state core, persists verbatim rows, advances its durable contiguous position, and acknowledges the prefix. There is no push, no background polling, no demand channel, and no per-Companion jobs on either side.

## Authority model

The Primary device is authoritative for durable conversation history (ADR 0025). The Companion proves its Primary by reading the server-assigned `deviceRole` (never inferring); the Primary proves each Companion as a same-user ACTIVE-bound device re-read from the server per batch. Role truth is always server-side; client role hints never authorize. Revoked devices fail closed on every operation. If no non-REVOKED Primary exists, synchronization is unavailable; no succession is invented.

## Initiation model

Companion-initiated pull only, attached to the existing manual Sync entry point. Primary upload is blind and idempotent (no demand signal needed; sequence dedupe absorbs redundancy) during its own manual sweep. Offline Primary yields stale/empty results (visible pending); offline Companion leaves pending server state untouched. No coupling between the two schedules beyond eventual convergence.

## Primary export model

Stream Room in server-sequence order with existing ordered queries; open each sealed BLOB transiently in memory (one item at a time, no bulk duplication); encrypt into the existing Primary→Companion Signal session; attach the per-conversation export frontier; upload. No export store and no export cursor persist on the Primary: regeneration from Room plus server-side dedupe makes restarts safe.

## Companion pull model

Fetch a sequence range for a conversation; resolve the currently-authorized Primary session (fresh directory role read, never cached past the operation); decrypt; validate the envelope; seal under the Companion vault; persist verbatim rows; recompute the durable contiguous position; prefix-ACK it. Unknown conversations, unparticipated conversations, and non-Primary senders are rejected fail-closed.

## Server pending-set model

Pending state is a set of opaque per-item rows keyed `(companionDeviceId, conversationId, sequenceNumber)` with a uniqueness constraint, plus independent batch receipts keyed by globally unique `syncBatchId`. There is no queue-head entity, no sync-cursor entity, and no batch container entity. Unacknowledged rows persist (TTL backstop); acknowledged prefixes evict; evicted-but-unacked data is regenerable from Primary Room under a new batch ID.

## Batch identity

`syncBatchId` is a globally unique UUID per upload. Identical canonical content under the same ID replays the stored receipt; divergent content under the same ID is a `409` conflict anywhere. A batch is an upload unit only; fetch and ACK never reference batch identity after upload.

## Item identity

`messageId` is the stable message identity and is unique within the sync namespace; Companion ingest dedupes on it through the existing insert-ignore path. Server sequence is the ordering coordinate, never an identity.

## Overlap semantics

Overlapping batches are allowed and absorbed by the uniqueness constraints: identical items are idempotent duplicates; the pending set is keyed by sequence, so eviction and fetch are prefix-scoped and batch-agnostic (e.g. batches 100–109 and 105–114 with ACK 107 leave exactly 108–114 pending).

## Conflict semantics

Same sequence + same messageId + same ciphertext → idempotent duplicate (receipt replay). Same sequence + different messageId, same sequence + messageId with divergent ciphertext, or same messageId at a different sequence → `409` conflict; the whole batch is rejected atomically with zero partial writes. Retrying the exact original batch replays the receipt.

## Encryption/envelope model

Each item is encrypted with the existing per-device Signal session between Primary and Companion (new envelope-type label for gating; no new primitive). The encrypted payload carries `conversationId`, `messageId`, `sequenceNumber`, original `senderDeviceId`, original `recipientDeviceId`, original `serverTimestamp`, message bytes, and the per-conversation export frontier. The server stores only opaque ciphertext plus routing metadata and stays blind, including to the frontier.

## Frontier semantics

Frontier = the Primary's `highestContiguous` durable sequence for the conversation at export, repeated per encrypted item. The Companion persists `lastSeenFrontier` beside its derived contiguous position: equal means complete-as-of-frontier, lower means pending, later-higher means sync may continue, regression is an explicit anomaly that is never silently accepted. The frontier is explicitly NOT authenticated completeness and does NOT recover history lost from Primary storage.

## Position/ACK model

ACK coordinate is `(companionDeviceId, conversationId, throughSequence)`, prefix-scoped, idempotent, and independent of batch identity. The existing mailbox/history delivery cursors are never read or written for sync. The Companion's durable position derives from Room contiguity; the server's pending head derives from unacked rows. No sync-cursor entity exists.

## Idempotency

`messageId` governs ingest idempotency; `syncBatchId` governs upload receipt replay. `messageRequestId` semantics are submit-domain and are not reused. Lost upload/fetch/ACK responses, retries, partial batches, and crashes all converge through receipt replay, range re-pull, ack re-send, and duplicate-absorbing ingest.

## Receipt semantics

Receipts are independent persisted records surviving item eviction, with their own (open) TTL. Authorization is evaluated before every replay: a revoked caller receives `403` even holding a valid receipt, so receipts can never bypass current authorization.

## Crash/restart behavior

Primary crashes lose nothing durable (Room is the source; server holds unacked work). Companion crashes resume from the durable contiguous prefix; redelivery lands in the duplicate path; cursor recomputation is pure. No distributed transaction is assumed; Room and Keystore remain separate durability systems with explicit ordered transitions.

## Revocation

Per-request ACTIVE/role revalidation on upload, fetch, and ACK. In-flight batches to a just-revoked Companion remain technically decryptable (accepted property, identical to delivered-but-unacked mailbox items). Re-enrollment mints new device IDs (never reused), so sync state starts clean. Primary revocation suspends synchronization; recovery elects a new Primary through the existing recovery flow, starting empty.

## Multi-Companion behavior

Up to four Companions sync through independent per-(Companion, conversation) pending sets, cursors, batch IDs, sessions, and locks. Offline, stalled, or revoked Companions never block others. No global lock, no global cursor, no cross-Companion coupling.

## Security invariants

E2EE confidentiality preserved; server blind (including frontier); Primary authority enforced by server roles plus pinned identities; conflicting sequence/message data rejected rather than substituted; at-least-once idempotent convergence; no silent completion (gaps and regressions visible); revocation checked per operation; no trust in client-declared roles; no gap markers; no plaintext server processing.

## Guarantees

Confidentiality; Primary-authoritative history; blind server; silent-substitution resistance; idempotent convergence when both devices participate; visible pending state; crash/restart convergence while Primary history remains intact; per-operation revocation; independent multi-Companion streams.

## Non-guarantees

Authenticated completeness; recovery of Primary-lost history; freshness while Primary is offline; push/realtime delivery; background synchronization; Primary succession; backup/restore; final retention policy.

## Rejected alternatives

Reusing message-submit (same-user ban, friendship gating, wrong conversation model, realtime side effects); mailbox/history reuse (destructive queue vs unauthorized cross-device reads); direct P2P (no channel, offline unsupportable); server-held plaintext or re-encryption (breaks server blindness); sync-cursor/queue-head/batch-container entities; provenance/originDeviceId column; gap markers; parallel ingest pipeline; second signature scheme; new crypto; background/push triggers; demand channel; succession design.

## Consequences

Slice 12 implementation (not started) requires: one new server pending-batch store with receipts, three sync endpoints with the composed authorization, and a thin Android coordinator reusing the existing ingest/DAO/crypto seams — with no Room migration and no crypto changes. The web Companion can reuse the same contract later.

## Deferred parameters/decisions

Endpoint paths, batch size caps, sync-batch and receipt TTL values, exact status/error-code names, envelope version number, Primary upload cadence within manual sweep, web-Companion deltas, liveness/expiry values, succession, backup, push/realtime sync.
