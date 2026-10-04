# Architecture Current State

Date: 2026-10-04.

This document describes the Android repository as it exists now. It does not describe future architecture as implemented behavior.

## Implemented

- Single Android application module (`:app`), package/application ID `com.samvaad.android`.
- Kotlin + Jetpack Compose + Material 3.
- `MainActivity : ComponentActivity` launches the Compose content.
- `SamvaadTheme` provides the generated Material 3 theme with dynamic color on Android 12+.
- One launcher activity is declared in the manifest.
- Gradle Kotlin DSL with version catalog.
- AGP `9.4.1`, Kotlin `2.2.10`, Compose BOM `2026.02.01`, Gradle `9.6.0`.
- `minSdk 30`, `compileSdk 37`, `targetSdk 37`.
- The unauthenticated UI is the Samvaad entry screen with server address, username, password, and Continue action. The authenticated Home surface now includes enrollment/approval/recovery state plus the Slice 11 conversation/history presentation. Input and presentation values remain local Compose UI state.
- Authentication uses `POST /api/auth/login` with `clientPlatform: "ANDROID"` over HTTPS. The live `AuthSession` remains an in-memory runtime object while its refresh bundle is sealed for restart recovery by the Slice 5 session store.
- The authenticated root uses `SessionGate` to restore the durable refresh session and routes between login and the authenticated Home boundary without a navigation framework.
- Host UI/unit tests cover the entry/auth/session boundaries with fakes and deterministic synchronization.
- The bootstrap has been verified to build and launch on a Pixel 6a API 33 emulator.
- Local-only libsignal feasibility spike (ADR 0003): `AndroidSignalAdapter` isolates `org.signal:libsignal-*` 0.86.5 and proves in-memory generation and parsing/verification of identity, signed-prekey, Kyber, and OTPK material on emulator and physical Pixel 6a. The AGPL distribution decision remains outstanding.
- Keystore-backed crypto vault (ADR 0004): `AndroidCryptoVault` seals libsignal record blobs under a non-exportable AES-256-GCM Keystore wrapping key into `getNoBackupFilesDir()`, with fail-closed corruption/missing-key handling and restart/reboot proof.
- First-device bootstrap enrollment (ADR 0005): `EnrollmentCoordinator` performs reconcile-first enrollment on the authenticated session, uploads exactly 100 OTPKs when ACTIVE, and exposes the 25 first-bootstrap recovery codes once with explicit acknowledgment.
- Durable refresh-token session (ADR 0006): `FileSessionStore` seals the refresh bundle in a separate no-backup namespace; access tokens remain memory-only. `SessionRefresher` performs launch-time single-flight refresh/rotation. Logout wipes only the auth-session record and leaves device/crypto state intact.
- Outbound Signal session establishment (ADR 0007): recipient device discovery and OTPK claim produce a validated, pinned `SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)` session. The durable `SessionRecord` is sealed before remote session metadata is recorded, and valid sessions are reused without rediscovery/claim.
- Slice 7 outbound encrypted message submission: `MessageSender` loads an existing established session, encrypts with real libsignal, persists the post-encrypt `SessionRecord` before HTTP submission, submits the existing server ciphertext envelope, and retries an ambiguous transport outcome with the same in-memory request bytes/request ID rather than re-encrypting.
- Slice 8 inbound mailbox consumption and Signal decryption: `InboxProcessor` fetches a small device-scoped mailbox batch, resolves each `senderDeviceId` against an existing `SignalSessionEntry`, selects `PREKEY_INIT` vs `RATCHET` from the server-supplied envelope type, decrypts through real libsignal 0.86.5, seals the post-decrypt `SessionRecord`, and only then acknowledges that message ID.
- Inbound duplicate processing is explicit: a libsignal `DuplicateMessageException` is treated as proof that the message was already processed when the durable local message row exists, so it is acknowledged without delivering plaintext again. Other decrypt/persistence failures remain unacknowledged for redelivery.
- Outbound and inbound session mutation share the same per-remote-device `SessionDeviceLocks` holder so one `SessionRecord` cannot be mutated concurrently in opposite directions.
- Companion approval and recovery UX (Slice 10): `HomeScreen` can manually re-query device state for pending/denied enrollment, an ACTIVE-bound device can approve pending devices, and recovery can either bind the session to an existing ACTIVE device or enroll a fresh device. Recovery codes are transient Compose state and are cleared after attempts or leaving the recovery surface.

### Slice 9 — Durable message state and reconciliation

Slice 9 adds the first durable local message-state boundary.

#### Room message-state store

Room is used for relational message/conversation facts:

- `ConversationEntity` tracks conversation identity, last-seen sequence, and locally asserted cursor-through sequence.
- `MessageEntity` tracks local/server identifiers, conversation/sequence, direction, device IDs, envelope type, ciphertext, sealed plaintext, send state, ACK state, request ID, server timestamp, and creation time.
- `MessageDao` provides idempotent inserts, state transitions, pending-work queries, history pages, message deduplication, and highest-contiguous sequence calculation.
- `MessageDatabase` is stored under `getNoBackupFilesDir()/message-state/messages.db`.
- Schema v1 is a fresh-install boundary; no destructive migration fallback was introduced.

Room stores message metadata and opaque/sealed BLOBs. It does not store private keys or Signal `SessionRecord` material.

#### Message content protection

`MessageContentSealer` reuses the existing Keystore wrapping-key infrastructure rather than introducing a second key hierarchy.

The sealed-message format uses the existing record-envelope mechanism with a dedicated message-content kind (`0x20`) and a deterministic per-message handle derived from the local message ID. Plaintext is sealed before durable insertion; Room never stores the plaintext bytes directly.

Structural Room metadata is not itself an encrypted database. The security boundary is specifically the sealed message-content BLOB plus the existing Keystore-held wrapping key.

#### Outbound state machine

Durable outbound submission follows:

`PENDING_SEAL → SEALED → SENT`

The logical message gets distinct local and server identifiers. The server-assigned message ID, sequence number, and server timestamp are recorded after acceptance.

A recoverable `SEALED` row re-submits the exact stored ciphertext/request ID. A stranded `PENDING_SEAL` row is opened from sealed plaintext, removed, and retried as a fresh logical submission rather than reusing an uncertain pre-accept request identity.

#### Inbound state machine

Durable inbound processing follows:

`DECRYPTED → SEALED → ACKED`

The plaintext is sealed before the message row is considered durable. The mutated Signal `SessionRecord` is also sealed before the mailbox entry is acknowledged.

A libsignal `DuplicateMessageException` is accepted as already-processed only when durable local message state proves the message exists. ACK then converges delivery without another plaintext delivery. Other decrypt/seal/persistence failures remain unacknowledged.

#### History and synchronization cursors

Android now consumes the existing server history and synchronization-cursor contracts:

- `GET /api/e2ee/conversations/{conversationId}/messages?afterSequence=&limit=`
- `GET /api/e2ee/sync?conversationId=`
- `PUT /api/e2ee/sync`

Server history is a reconciliation/replay source. Durable local message state remains the local source of truth for whether content has been successfully processed and stored.

Cursor advancement is **contiguous-only**. If local durable sequences are `1,2,3,5`, the highest contiguous sequence is `3`; the cursor cannot advance through the gap at `4`. Cursor writes are also bounded by the server's reported conversation sequence.

#### Reconciliation sweep

`ReconciliationSweep` is a bounded, deterministic, idempotent headless operation:

1. recover outbound rows;
2. reconcile unacknowledged mailbox work and mailbox redelivery;
3. reconcile history for known conversations;
4. advance synchronization cursors only through locally contiguous durable state.

The sweep uses bounded mailbox/history limits and a bounded history-page count. It has no scheduler, background worker, push trigger, or realtime dependency.

The same `SessionDeviceLocks` holder must be shared by outbound, inbound, and reconciliation paths so SessionRecord mutation remains serialized per remote device.

The current app does not automatically invoke `ReconciliationSweep`; Slice 9 establishes and tests the headless capability. There is no scheduler/background worker/push trigger or user-facing chat/history surface yet.

#### Cross-store crash model

Room and Android Keystore are separate durability systems and are not treated as a distributed transaction.

Instead, Slice 9 uses explicit durable state transitions and idempotent re-entry:

- outbound `SEALED` is safe to replay exactly;
- outbound `PENDING_SEAL` is recoverable from sealed plaintext;
- inbound durable rows absorb mailbox redelivery;
- ACK failure leaves the message eligible for duplicate convergence;
- cursor failure leaves the message durable/ACKED and allows later cursor retry.

No two-phase commit or hidden atomicity assumption is used.

### History ownership boundary

The server's ciphertext history remains a transition-state delivery/replay mechanism. Server ADR 0025 continues to define Android Primary ownership of durable conversation history and the future Primary-to-Companion synchronization direction.

Slice 9 implements **local durable message state and reconciliation**, not the final Companion history protocol, server retention policy, backup/restore, or a user-facing history experience.

### Slice 10 — Existing-device Companion approval and recovery UX

Slice 10 adds the Android-side UX/state boundary for server-defined device approval and recovery:

- Pending enrollment is surfaced with a manual **Check status** action. Android re-queries GET /api/e2ee/devices rather than polling.
- An ACTIVE-bound device can list pending devices and approve one through the existing approval endpoint. A pending/unbound device never exposes approval controls.
- A server-revoked pending device converges to a distinct denied state. The user can explicitly start a fresh enrollment; the old device identity is not silently reused as a new attempt.
- Recovery accepts a code only transiently and offers two explicit server-supported paths: bind the session to an existing ACTIVE device, or recover-enroll a new device.
- Bind adopts server device state without receiving private key material. If the installation has no local crypto handles, the UI reports **Device bound** rather than falsely claiming full messaging readiness. Messaging paths retain their fail-closed missing-key guards; the recovery-as-new path is the route to create local messaging keys.
- Recovery enrollment creates new local crypto material through the existing enrollment path and then uploads the existing 100-OTPK bootstrap batch. Recovery-code rotation is not implemented.
- Approval/recovery outcomes are converged through authoritative device listing; no blind retry, background polling, push, or realtime mechanism was introduced.

The Slice 10 authenticated server round-trip was not completed in the development environment because no safe test credentials were available. The Android implementation is covered by contract/unit/UI tests and unauthenticated/TLS checks; no server state was mutated for validation.

### Slice 11 — Primary-owned durable conversation history presentation and behavior

Slice 11 turns the existing durable message-state boundary into a user-facing Primary conversation/history surface without adding a new server protocol or persistence layer.

#### Conversation list and detail

- HomeScreen constructs one explicit messaging graph for the authenticated surface and reuses the existing Room database, Keystore-backed MessageContentSealer, SessionMetadataStore, MessageSender, SessionEstablisher, and ReconciliationSweep.
- The conversation list is derived from known durable conversation IDs and recent locally stored message rows.
- Conversation detail renders locally durable messages in server sequence order.
- Sealed message content is opened only in memory for rendering. Unreadable/corrupt sealed content is represented by a safe placeholder rather than raw bytes.
- Conversation navigation is local Compose state with BackHandler; no Navigation Compose or ViewModel/DI framework was introduced.
- An installation without local crypto handles remains explicitly Device bound and does not expose messaging UI; existing fail-closed messaging guards remain authoritative.

#### Manual reconciliation and sending

- Sync is an explicit user action. It invokes the existing bounded ReconciliationSweep, then reloads the Room-backed list/detail state.
- Existing durable messages remain visible when synchronization reports partial failures.
- The composer requires an explicit friend username, uses the existing friendship-gated recipient directory, and requires explicit selection of one recipient device.
- Sending reuses the existing SessionEstablisher and MessageSender; it does not introduce a second encryption/submission path.
- Successful submission refreshes the local conversation/detail view from durable Room state. UI exposes only local queued/sending/sent-oriented state and safe errors; it does not expose ciphertext or cryptographic material.
- Duplicate taps are guarded at the UI level so only one logical send runs at a time.

#### Restart and offline behavior

- The conversation list/detail surfaces can render durable sealed message content without a network call after process restart.
- Room remains the local source of truth for presentation; server history remains reconciliation/replay input.
- Slice 11 does not add background polling, push, WebSocket/STOMP, Primary-to-Companion history sync, server retention/eviction, backup/restore, or new server endpoints.
## Slice 12 — Primary-to-Companion history synchronization

Slice 12 implements the frozen Primary-to-Companion history-sync protocol from ADR 0026.

### Server foundation

The server now provides the opaque pending-set and receipt foundation used by Android:

- `POST /api/e2ee/sync-history/batches` for Primary upload;
- `GET /api/e2ee/sync-history/batches` for Companion range fetch;
- `POST /api/e2ee/sync-history/ack` for prefix acknowledgment.

The server authorizes each operation from the session-bound device and current server-assigned role. Upload requires an ACTIVE PRIMARY targeting an ACTIVE same-user COMPANION; fetch and ACK require the ACTIVE COMPANION. Conversation participation and current authorization are revalidated per operation.

Pending items are opaque server-side rows keyed by Companion, conversation, and sequence. Global `syncBatchId` receipts survive item eviction for idempotent replay and conflict detection. Upload is whole-batch atomic; overlapping identical items converge, while sequence/message conflicts fail with `409`. Pending items and receipts use the implemented seven-day lazy TTL policy. No server plaintext processing, sync cursor, batch container, succession, liveness, push, or background scheduler was introduced.

### Android Primary export

An ACTIVE PRIMARY can manually and boundedly export durable local history to ACTIVE Companions.

The Primary:

1. derives the conversation frontier from the highest contiguous durable Room sequence;
2. reads durable messages in server-sequence order;
3. opens sealed message content only in memory;
4. binds conversation/message/sequence/original-device metadata and the export frontier into the versioned encrypted sync payload;
5. encrypts through the existing Primary→Companion Signal session;
6. uploads bounded single-conversation batches with a stable `syncBatchId` for transport retry.

The Primary has no separate export store or export cursor. Room remains the durable history authority.

### Android Companion import

An ACTIVE COMPANION manually fetches pending ranges and decrypts them through the existing Signal/session infrastructure.

The sync ingest path resolves the exporting Primary session separately from the historical message's original `senderDeviceId`. The original sender/recipient metadata is preserved verbatim in the durable Room row.

Synced messages use the existing message model as inbound durable history state. Plaintext is sealed before persistence, and ACK is sent only through the highest contiguous locally durable sequence. Duplicate delivery, gaps, transport failure, and crash/restart converge through the existing durable-state and idempotent retry model.

The Companion stores `lastSeenFrontier` in the existing no-backup metadata-store pattern. Room contiguity remains authoritative for ACK safety; metadata can never advance the durable position by itself. A frontier regression is surfaced as an anomaly rather than silently accepted.

### Trigger and concurrency

History synchronization is attached to the existing manual Sync action. There is no new screen, scheduler, background worker, push trigger, realtime transport, or demand channel.

`SessionDeviceLocks` serializes Primary→Companion Signal session mutation with existing messaging paths. Multiple conversations and Companions remain independently bounded.

### Current boundary

Slice 12 does not implement backup/restore, server retention policy, Primary succession, liveness expiry, push/background synchronization, or Web Companion behavior. The server remains blind to history plaintext and the encrypted frontier.
## Not implemented

- WebSocket/STOMP realtime integration.
- Background mailbox polling or push notification handling.
- Automatic/background access-token refresh beyond launch-time restoration; no generic 401 middleware.
- Recovery-code rotation and any broader device-revocation UX beyond the existing denied/pending convergence path.
- OTPK replenishment and Kyber rotation.
- Identity verification/fingerprint UI and a user-facing trust-state machine.
- Primary-to-Companion history synchronization.
- Wrapping-key rotation/lifecycle policy.
- Encrypted backup/restore.
- Server ciphertext retention/eviction implementation.
- Final Primary/Companion liveness policy.
- Final history-sync wire protocol.

## Server architecture relevant to Android

The current public server implementation baseline is:

`cbd87053d788cd44c73be9f3d3441f18c04ce88e`
(`fix: harden primary-to-companion history sync`).

The server has implemented:

- server-assigned device roles: one non-revoked PRIMARY plus up to four non-revoked COMPANIONS;
- five-device non-revoked cardinality enforcement;
- E2EE device enrollment, prekey/recovery foundations, session/device binding and device approval/revocation flows;
- ciphertext-only message submission;
- per-device mailbox and acknowledgement;
- per-device durable ciphertext history;
- per-conversation synchronization cursors;
- best-effort device-level realtime delivery with durable mailbox fallback.

The server remains cryptographically blind.

## Android architecture decisions not yet made

No Android-specific production architecture has been selected yet for:

- networking library;
- navigation;
- ViewModel/state-management structure;
- dependency injection.

Room is now selected for the Slice 9 durable message-state boundary. This does not establish a broader application persistence architecture beyond the message-state needs implemented here.

## Parked / future clients

- TUI is parked and remains useful for testing/companion behavior.
- The standalone `samvaad-e2ee-lib` MessageStore implementation is parked.
- Web is a future Companion client and has no implementation in this repository.

## What this is not

- not a user-facing chat experience;
- not a server-side history implementation;
- not the final Primary-to-Companion history-sync protocol;
- not a background/realtime delivery system;
- not an encrypted backup/restore implementation;
- not a claim that Room and Keystore form one atomic transaction.
