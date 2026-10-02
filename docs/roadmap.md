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

## Next

### Slice 9 — Message-state and history reconciliation

The next slice should define how consumed mailbox envelopes become durable client message state and how that state relates to the server's existing durable history and synchronization cursors.

This begins with an architecture audit of the current Android message-transport state and the actual server history/cursor implementation. Do not implement before the audit establishes the required invariants and the smallest persistence boundary.

The local persistence model is intentionally **not locked yet**. Room, DataStore, or another persistence framework must not be introduced until that boundary is explicitly decided.

Slice 9 remains separate from:

- Companion approval/recovery;
- Primary-owned durable history;
- Primary-to-Companion history synchronization;
- realtime/push delivery;
- OTPK replenishment and Kyber rotation.

## Subsequent planned slices

10. Existing-device Companion approval and recovery UX.
11. Primary-owned durable conversation history.
12. Primary-to-Companion history synchronization once its protocol is defined.
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
