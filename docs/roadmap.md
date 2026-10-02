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

- The generated greeting is replaced with the first Samvaad-specific
  screen: Samvaad branding/title, server address input, username input,
  Continue action.
- Established the entry screen with local Compose UI state (Continue's
  local demo confirmation was replaced by real authentication in
  Slice 2).
- No networking, authentication, persistence, navigation, device
  enrollment, or E2EE.
- Robolectric-based Compose UI tests cover the entry screen. They are
  test infrastructure only, not production architecture.

### Slice 2 — Authentication boundary

DONE.

- Continue performs a real `POST /api/auth/login` with
  `clientPlatform: "ANDROID"`; in-memory `AuthSession` only.
- Password field with obscured input; safe loading/error UI;
  duplicate-submit guard.
- Fake-`AuthApi` host tests cover request shape, success/failure UI,
  no-leak, and duplicate-submit behavior.
- No persistent credentials, no automatic refresh, no logout UI, no
  device enrollment, no E2EE.

### Slice 3 — Authenticated session boundary

DONE.

- Successful login transitions from the entry form to a placeholder
  `HomeScreen` showing the authenticated identifier and an explicit
  device-setup placeholder; failed login stays on the entry form.
- `HomeScreen` receives the identifier string only, never the session
  object or tokens. No navigation framework, no enrollment, no E2EE.

### Slice 4 — First-device bootstrap enrollment

DONE.

- `HomeScreen` drives first-device setup through `EnrollmentCoordinator`:
  sealed crypto reuse-or-generation with a durable attempt marker,
  reconcile-first `POST /api/e2ee/devices` on the login session
  (`409` triggers reconciliation, never blind retry), exactly-100 OTPK
  upload when ACTIVE, and one-shot transient display of the 25 recovery
  codes with explicit acknowledgment.
- Server echoes are verified before trust; server status/role/approval
  state is re-read and always overrides the local non-secret cache.
  PENDING responses stop safely with no upload and no approval UI.
- Fake-API coordinator tests, `ServerSocket`-stub transport tests, and
  the existing vault/adapter coverage guard the slice. Companion
  approval, recovery flows, messaging, auth persistence, and Room remain
  out of scope (ADR 0005).

### Slice 5 — Authenticated session persistence and restart

DONE.

- Refresh-token session bundle is sealed under the existing Keystore wrapping key in a separate no-backup namespace; access tokens remain memory-only.
- Launch-time silent refresh uses single-flight rotation.
- Logout best-effort revokes the server session and always wipes the local auth-session record without touching device/crypto state.
- Root `SessionGate` restores Home or returns to login without introducing a navigation framework.

### Slice 6 — Outbound Signal session establishment

DONE.

- Recipient devices are discovered through the existing `GET /api/e2ee/users/{username}/devices` contract.
- Establishment targets exactly one explicit remote `deviceId`; multiple ACTIVE devices are never auto-selected.
- Each OTPK claim uses a fresh UUID `requestId`; a bounded conflict retry uses a new request ID.
- Signed-prekey and Kyber signatures are verified locally before libsignal processing. Missing Kyber is rejected for this path.
- `SignalProtocolAddress` uses `(remoteUsername, remoteSignalDeviceId)` for Android V1.
- `SessionBuilder.process()` creates the outbound session and `hasSenderChain()` gates readiness.
- The canonical `SessionRecord.serialize()` bytes are sealed as `SESSION (0x05)` under the existing Keystore wrapping key. Remote session metadata is stored separately and pins the remote identity.
- Valid sessions are reused without a second claim or session build. Failed post-claim establishment never reuses the claimed OTPK.
- Restart recovery has been proven on the emulator and physical Pixel 6a, including encryption after restoration.
- This slice does not send a message; it proves durable outbound session readiness.

## Next

### Slice 7 — Outbound encrypted message submission

The next implementation slice should connect an already-established Signal session to the existing server ciphertext-submission contract.

The slice must remain narrow: construct a real encrypted Signal ciphertext for an explicitly selected remote device and submit the corresponding PREKEY_INIT/RATCHET envelope through the existing server API. Message UI, inbound mailbox/decryption, conversation history, realtime delivery, and synchronization remain separate slices.

Do not start it without an explicit implementation contract and codebase audit.

## Subsequent planned slices

8. Inbound mailbox consumption and Signal decryption.
9. Mailbox acknowledgment and conversation/history/cursor reconciliation.
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
