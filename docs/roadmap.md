# Android Roadmap

The Android roadmap is incremental. Each slice should be small, buildable, reviewable, and stopped before unrelated architecture is introduced.

## Completed

### Slice 0 — Repository bootstrap

DONE.

- Android Studio Compose baseline established.
- Repository documentation/ADR foundation established.
- Git history established and repository published.
- Build/test baseline verified.
- Android is designated as the Primary product device client by ADR 0001.

### Slice 1 — Basic Samvaad entry UI

DONE.

- The generated greeting is replaced with the Samvaad-specific entry screen: branding/title, server address, username, password, and Continue.
- The screen remains local Compose UI; real authentication is introduced in Slice 2.
- Robolectric-based Compose UI tests cover the observable entry behavior.

### Slice 2 — Authentication boundary

DONE.

- Continue performs a real `POST /api/auth/login` with `clientPlatform: "ANDROID"`; access/refresh/session values are held in the in-memory `AuthSession` for the live session.
- Password input is obscured; loading/error UI is safe; duplicate submission is guarded.
- Fake-`AuthApi` tests cover request shape, success/failure UI, no-leak, and duplicate-submit behavior.
- Persistent authentication, device enrollment, and E2EE remain outside this slice.

### Slice 3 — Authenticated session boundary

DONE.

- Successful login transitions to the authenticated `HomeScreen` boundary without introducing a navigation framework.
- Only the identifier reaches the Home UI; tokens and session objects remain outside UI code.
- No enrollment or E2EE is implemented by this slice.

### Slice 4 — First-device bootstrap enrollment

DONE.

- `EnrollmentCoordinator` reuses sealed material or generates it exactly once, records an attempt marker before enrollment, reconciles on uncertain outcomes, uploads exactly 100 OTPKs when the first device is ACTIVE, and handles the one-shot recovery-code display/acknowledgment.
- Server status/role/approval remains authoritative.
- Companion approval, recovery UX, messaging, and local message persistence remain out of scope.

### Slice 5 — Authenticated session persistence and restart

DONE.

- Refresh-token session bundle is sealed under the existing Keystore wrapping key in a separate no-backup namespace; access tokens remain memory-only.
- Launch-time silent refresh uses single-flight rotation.
- Logout best-effort revokes the server session and wipes the local auth-session record without touching device/crypto state.
- `SessionGate` restores Home or login without a navigation framework.

### Slice 6 — Outbound Signal session establishment

DONE.

- Recipient devices are discovered through the existing friendship-gated directory contract.
- Establishment targets exactly one explicit remote `deviceId`; multiple ACTIVE devices are never auto-selected.
- Each OTPK claim uses a fresh UUID `requestId`; a bounded conflict retry uses a new request ID.
- Signed-prekey and Kyber signatures are verified locally before libsignal processing. Missing Kyber is rejected for this path.
- `SignalProtocolAddress` uses `(remoteUsername, remoteSignalDeviceId)` for Android V1.
- `SessionBuilder.process()` creates the outbound session and `hasSenderChain()` gates readiness.
- The canonical `SessionRecord.serialize()` bytes are sealed as `SESSION (0x05)` under the existing Keystore wrapping key. Remote session metadata is stored separately and pins the remote identity.
- Valid sessions are reused without a second claim or session build. Failed post-claim establishment never reuses the claimed OTPK.
- Restart recovery has been proven on the emulator and physical Pixel 6a, including encryption after restoration.
- This slice does not send a message; it proves durable outbound session readiness.

### Slice 7 — Outbound encrypted message submission

DONE.

- An established session is reused without rediscovery or a new OTPK claim.
- Real libsignal encryption produces `PREKEY_INIT` or `RATCHET` based on the libsignal ciphertext type.
- The post-encrypt `SessionRecord` is sealed before the message HTTP submission.
- The existing `POST /api/e2ee/messages` contract is consumed with one request ID and one explicit recipient-device envelope.
- Ambiguous transport outcomes can be retried from the same in-memory request bytes and request ID; the message is never re-encrypted for that logical attempt.
- No message UI, inbound processing, history, realtime, or synchronization was introduced.

### Slice 8 — Inbound mailbox consumption and Signal decryption

DONE.

- `InboxProcessor` consumes a small device-scoped mailbox batch (default 20) through the existing mailbox API.
- Each entry resolves `senderDeviceId` to an already-established `SignalSessionEntry`; unknown senders are skipped without discovery, claims, or new session creation.
- `envelopeType` is the explicit protocol discriminant: `PREKEY_INIT` uses `PreKeySignalMessage`, `RATCHET` uses `SignalMessage`.
- Real libsignal 0.86.5 decrypts the ciphertext and returns plaintext only in memory.
- The mutated `SessionRecord` is exported and sealed before that message ID is acknowledged.
- `DuplicateMessageException` is treated as proof of prior processing and acknowledges the mailbox entry without redelivering plaintext.
- All other decrypt or persistence failures remain unacknowledged.
- A shared per-remote-device lock serializes outbound and inbound SessionRecord mutation.
- No local message store, history, cursor reconciliation, realtime, background polling, push, or UI was introduced.

### Slice 9 — Durable message state and history reconciliation

DONE.

- Room `MessageDatabase` persists durable conversation/message facts under `getNoBackupFilesDir()`.
- `MessageContentSealer` protects message plaintext at rest with the existing Keystore wrapping-key infrastructure; private keys and Signal `SessionRecord` material remain in the crypto vault.
- Outbound recovery uses `PENDING_SEAL → SEALED → SENT`; sealed accepted bytes/request IDs can be replayed exactly, while stranded pending rows are safely rebuilt from sealed plaintext.
- Inbound recovery uses durable message rows before ACK; mailbox redelivery converges through the durable-row/duplicate path.
- Server-assigned message identifiers and sequence/timestamp metadata are persisted separately from local message IDs.
- Android consumes the existing conversation-history and synchronization-cursor APIs.
- Cursor advancement is contiguous-only and never skips sequence gaps.
- `ReconciliationSweep` is bounded and idempotent, covering outbox recovery, mailbox/ACK reconciliation, known-conversation history ingestion, and cursor advancement.
- Room and Keystore are separate durability systems; recovery is achieved with explicit state machines rather than a fake cross-store transaction.
- No scheduler, background worker, push, realtime, chat UI, Companion history sync, backup, or server change was introduced.

## Next

### Slice 10 — Existing-device Companion approval and recovery UX

DONE.

- Pending enrollment is surfaced with manual GET /api/e2ee/devices status re-query; there is no polling.
- An ACTIVE-bound device can review and approve pending devices using the existing approval contract.
- Revoked/denied pending enrollment converges to a distinct denied state and can be restarted as a fresh enrollment.
- Recovery accepts a transient code and supports both existing-device bind and recover-enroll-new-device using the existing server contracts.
- Bind does not carry private keys. A bind-adopted installation without local crypto handles is explicitly shown as **Device bound** and remains unable to perform messaging until recovery-as-new creates local keys.
- Recovery enrollment uses the normal local crypto generation path and existing 100-OTPK upload.
- Recovery-code rotation, polling, push, realtime, Primary-gated approval, succession, and liveness remain outside this slice.
- No server implementation changes were made.
- The authenticated real-server round-trip was not completed because safe credentials were unavailable; no server state was mutated for that validation gap.

## Completed

### Slice 11 — Primary-owned durable conversation history presentation and behavior

DONE.

- The authenticated Home surface now presents a Room-backed conversation list and conversation detail view from durable local message state.
- Sealed message content is opened only in memory for presentation; unreadable content fails closed to a safe placeholder.
- Manual Sync invokes the existing bounded ReconciliationSweep and reloads durable conversation/detail state. There is no background polling, push, or realtime trigger.
- The composer requires an explicit friend username, uses the existing friendship-gated recipient directory, and requires explicit selection of one recipient device.
- Sending reuses the existing SessionEstablisher and MessageSender, then reloads the durable local row returned by the existing message-submission contract.
- Conversation navigation remains local Compose state with BackHandler; no Navigation Compose, ViewModel, or DI framework was introduced.
- Empty, loading, error, partial-sync, offline/restart, and handle-less Device bound states are covered by UI tests.
- Slice 11 added no server endpoint, persistence mechanism, cryptographic primitive, realtime transport, or background worker.

## Next

### Slice 12 — Primary-to-Companion history synchronization

Protocol frozen / ADR proposed — implementation pending.

ADR 0026 proposes the Primary-to-Companion history-sync protocol (Companion-initiated manual pull over a minimal server-mediated opaque pending-set with prefix ACK; Primary-authoritative history; no new crypto; no Room migration). The protocol is accepted as a design direction and frozen as a candidate; Slice 12 implementation has NOT started, the server has NOT changed, and no sync endpoints exist in code. The next step is the actual Slice 12 implementation against the frozen protocol. Do not invent protocol details beyond ADR 0026.

## Subsequent planned slices

13. Web Companion client after the Android Primary vertical slice.

These are sequencing directions, not permission to implement future protocol details early.

## Explicitly deferred

- exact server ciphertext-buffer retention/eviction policy;
- final Primary/Companion liveness/expiry policy;
- Primary-to-Companion history-sync wire protocol;
- encrypted backup/restore design;
- push notification design;
- group E2EE / MLS;
- nonessential messaging features such as read receipts, typing/presence, edits, replies, attachments, and reactions.

## Parked

- TUI feature development.
- `samvaad-e2ee-lib` MessageStore implementation.
