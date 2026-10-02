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
- Inbound duplicate processing is explicit: a libsignal `DuplicateMessageException` is treated as proof that the message was already processed, so it is acknowledged without delivering plaintext again. Other decrypt/persistence failures remain unacknowledged for redelivery.
- Outbound and inbound session mutation share the same per-remote-device `SessionDeviceLocks` holder so one `SessionRecord` cannot be mutated concurrently in opposite directions.
- Inbound identity remains pinned to the existing remote session metadata; changed/mismatched identity fails closed. Unknown `senderDeviceId` entries are skipped without discovery, OTPK claim, or session creation.
- Slice 8 keeps plaintext memory-only and does not introduce message/conversation persistence, history, synchronization, realtime, background polling, or UI.

## Not implemented

- User-facing chat UI.
- Local conversation/message persistence or durable message store.
- History reads and synchronization-cursor reconciliation.
- WebSocket/STOMP realtime integration.
- Background mailbox polling or push notification handling.
- Automatic/background access-token refresh beyond launch-time restoration; no generic 401 middleware.
- Enrollment beyond first-device bootstrap: Companion approval UI, recovery enrollment/entry/rotation, and revocation UX.
- OTPK replenishment and Kyber rotation.
- Identity verification/fingerprint UI and a user-facing trust-state machine.
- Primary-owned durable conversation history.
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
- not a claim that the Android app has a user-facing chat experience;
- not a history-sync implementation;
- not a server-side implementation;
- not a claim that Android already owns durable chat history.
