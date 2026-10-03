# Architecture Current State

Date: 2026-10-03.

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
- The current UI is the Samvaad entry screen with server address, username, password, and Continue action. Input values are local Compose UI state until authentication succeeds.
- Authentication uses `POST /api/auth/login` with `clientPlatform: "ANDROID"` over HTTPS. The live `AuthSession` remains an in-memory runtime object while its refresh bundle is sealed for restart recovery by the Slice 5 session store.
- The authenticated root uses `SessionGate` to restore the durable refresh session and routes between login and the authenticated Home boundary without a navigation framework.
- Host UI/unit tests cover the entry/auth/session boundaries with fakes and deterministic synchronization.
- The bootstrap has been verified to build and launch on a Pixel 6a API 33 emulator.
- Local-only libsignal feasibility spike (ADR 0003): `AndroidSignalAdapter` isolates `org.signal:libsignal-*` 0.86.5 and proves in-memory generation and parsing/verification of identity, signed-prekey, Kyber, and OTPK material on emulator and physical Pixel 6a. The AGPL distribution decision remains outstanding.
- Keystore-backed crypto vault (ADR 0004): `AndroidCryptoVault` seals libsignal record blobs under a non-exportable AES-256-GCM Keystore wrapping key into `getNoBackupFilesDir()`, with fail-closed corruption/missing-key handling and restart/reboot proof.
- First-device bootstrap enrollment (ADR 0005): `EnrollmentCoordinator` performs reconcile-first enrollment on the authenticated session, uploads exactly 100 OTPKs when ACTIVE, and exposes the 25 first-bootstrap recovery codes once with explicit acknowledgment. Companion approval and recovery UX remain absent.
- Durable refresh-token session (ADR 0006): `FileSessionStore` seals the refresh bundle in a separate no-backup namespace; access tokens remain memory-only. `SessionRefresher` performs launch-time single-flight refresh/rotation. Logout wipes only the auth-session record and leaves device/crypto state intact.
- Outbound Signal session establishment (ADR 0007): recipient device discovery and OTPK claim produce a validated, pinned `SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)` session. The durable `SessionRecord` is sealed before remote session metadata is recorded, and valid sessions are reused without rediscovery/claim.
- Slice 7 outbound encrypted message submission: `MessageSender` loads an existing established session, encrypts with real libsignal, persists the post-encrypt `SessionRecord` before HTTP submission, submits the existing server ciphertext envelope, and retries an ambiguous transport outcome with the same in-memory request bytes/request ID rather than re-encrypting.
- Slice 8 inbound mailbox consumption and Signal decryption: `InboxProcessor` fetches a small device-scoped mailbox batch, resolves each `senderDeviceId` against an existing `SignalSessionEntry`, selects `PREKEY_INIT` vs `RATCHET` from the server-supplied envelope type, decrypts through real libsignal 0.86.5, seals the post-decrypt `SessionRecord`, and only then acknowledges that message ID.
- Inbound duplicate processing is explicit: a libsignal `DuplicateMessageException` is treated as proof that the message was already processed when the durable local message row exists, so it is acknowledged without delivering plaintext again. Other decrypt/persistence failures remain unacknowledged for redelivery.
- Outbound and inbound session mutation share the same per-remote-device `SessionDeviceLocks` holder so one `SessionRecord` cannot be mutated concurrently in opposite directions.

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

## Not implemented

- User-facing chat UI and conversation/history presentation.
- WebSocket/STOMP realtime integration.
- Background mailbox polling or push notification handling.
- Automatic/background access-token refresh beyond launch-time restoration; no generic 401 middleware.
- Enrollment beyond first-device bootstrap: Companion approval UI, recovery enrollment/entry/rotation, and revocation UX.
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

`164463da10505c2b789556e02536e2f1e8701cf5`
(`feat: enforce primary and companion device roles`).

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
