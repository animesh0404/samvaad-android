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

## Next

The next slice follows the existing sequencing direction below
(item 2 under "Subsequent planned slices"). No implementation contract
for it is defined yet; do not start it without an explicit slice
definition.

## Subsequent planned slices

These are sequencing directions, not already-defined implementation contracts.

1. Entry/authentication boundary against the existing server authentication contract.
2. First-device bootstrap and E2EE enrollment.
3. Secure persistent device/cryptographic state.
4. Existing-device approval and recovery flows.
5. E2EE session establishment and encrypted message transport.
6. Mailbox, history, acknowledgement, and synchronization-cursor reconciliation.
7. Primary-owned durable conversation history.
8. Primary-to-Companion history synchronization when its protocol is defined.
9. Web Companion client after the Android Primary vertical slice.

A slice must stop and surface an architectural decision if the required server contract or client-side security design is not already defined.

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
