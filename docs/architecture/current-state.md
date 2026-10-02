# Architecture Current State

Date: 2026-10-02.

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
- The current UI is the Slice 1 Samvaad entry screen: Samvaad
  branding/title, server address input, username input, password input,
  and a Continue action. Inputs are local Compose UI state only.
- Slice 2 authentication: Continue performs a real HTTP
  `POST /api/auth/login` against the configured server address
  (`HttpURLConnection` + `org.json`; no networking library) with
  `clientPlatform: "ANDROID"`, explicit-null `installationId`, and the
  optional `clientName`/`clientVersion` omitted. Success keeps an
  in-memory `AuthSession` (access/refresh tokens, sessionId) and
  transitions to a placeholder `HomeScreen` showing only the
  authenticated identifier plus an explicit device-setup placeholder;
  the session object never reaches UI code. The password is cleared
  from UI state on success. Failures show fixed safe messages;
  duplicate submissions are guarded.
- Host unit tests include Slice 1 Robolectric-based Compose UI tests
  (`EntryScreenTest`: branding, inputs, text entry) extended in Slice 2
  with a fake `AuthApi` boundary (request shape, success/failure UI,
  no-leak, duplicate-submit) alongside the generated `ExampleUnitTest`
  template. The instrumented package-name template remains. The
  Robolectric setup is test infrastructure only, not production
  architecture.
- The bootstrap has been verified to build and launch on a Pixel 6a API 33 emulator.
- Local-only libsignal feasibility spike (ADR 0003): `AndroidSignalAdapter`
  isolates `org.signal:libsignal-*` 0.86.5 and proves in-memory generation
  of identity/signed-prekey/Kyber/OTPK material with libsignal
  parse/verify semantics on the Pixel 6a API 33 x86_64 emulator and a
  physical Pixel 6a (arm64-v8a). No enrollment, no persistence, no
  messaging; AGPL distribution decision outstanding.
- Keystore-backed crypto vault (ADR 0004): `AndroidCryptoVault` seals
  libsignal record blobs under a non-exportable AES-256-GCM Keystore
  wrapping key into `getNoBackupFilesDir()`; fail-closed on
  missing-key/corruption/version mismatch; restart- and reboot-proven.
- First-device bootstrap enrollment (ADR 0005): `EnrollmentCoordinator`
  drives `POST /api/e2ee/devices` on the login session (reconcile-first,
  attempt marker, `409`-as-reconcile-trigger), uploads exactly 100 OTPKs
  when ACTIVE, and shows the 25 first-bootstrap recovery codes once with
  explicit acknowledgment. Companion approval, recovery flows, and
  messaging do not exist.
- Durable refresh-token session (ADR 0006): `FileSessionStore` seals
  the refresh bundle (server address, identifier, refresh token,
  session ID, refresh expiry) under the same Keystore wrapping key in a
  separate `getNoBackupFilesDir()/session/` namespace; access tokens stay
  memory-only. `SessionRefresher` restores on launch with single-flight
  rotation, wipes on rejection, and never touches device/crypto state on
  logout. Root `SessionGate` routes to Home or login with safe messages.

## Not implemented

- Message transport: no `POST /api/e2ee/messages`, mailbox consumption/acknowledgment, history reads, synchronization-cursor reconciliation, or WebSocket/STOMP integration.
- Inbound Signal message decryption and receive-side session handling.
- Automatic/background token refresh beyond launch-time restoration; no generic 401 middleware.
- Enrollment beyond first-device bootstrap: Companion approval UI, recovery enrollment/entry/rotation, and revocation UX.
- OTPK replenishment trigger and Kyber rotation flow.
- Identity verification/fingerprint UI and a user-facing trust-state machine.
- Local conversation/message database or durable message store.
- Navigation, ViewModel, dependency injection, background work, and push notifications.
- Primary-to-Companion history synchronization.
- Wrapping-key rotation/lifecycle policy.
- Encrypted backup/restore.

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

The server remains cryptographically blind to message content.

## Transition state vs target architecture

The server's per-device durable ciphertext history is currently a **transition-state implementation**. It is not yet the final long-term history architecture.

Target direction established by server ADR 0025:

- Android is the Primary product device.
- Primary owns durable conversation history.
- Web is a future Companion.
- The server becomes a bounded delivery/replay layer rather than the user's permanent chat archive.
- Companion history is obtained through an E2EE Primary-to-Companion synchronization mechanism.

Not yet locked or implemented:

- exact server retention/eviction count and semantics;
- final Primary/Companion liveness/expiry policy;
- Primary-to-Companion history-sync wire protocol;
- encrypted backup/restore design.

Therefore Android must not implement or assume any of those details until explicitly defined.

## Android architecture decisions not yet made

No Android-specific production architecture has been selected yet for:

- networking library;
- persistence/database technology;
- navigation;
- ViewModel/state-management structure;
- dependency injection.

These decisions should be made when their corresponding implementation slices require them.

## Parked / future clients

- TUI is parked and remains useful for testing/companion behavior.
- The standalone `samvaad-e2ee-lib` MessageStore implementation is parked.
- Web is a future Companion client and has no implementation in this repository.

## What this is not

- not a TUI architecture port;
- not an E2EE implementation;
- not a history-sync implementation;
- not a server-side implementation;
- not a claim that Android already owns durable chat history.
