# Samvaad Android

Native Android client for Samvaad, built with Kotlin and Jetpack Compose.

Android is the **PRIMARY product device**. Web is a future COMPANION client. TUI remains parked/testing-oriented.

## Current state

Slices 0–8 are complete.

The app is a single-`:app`-module Compose application with Samvaad branding, HTTPS authentication, durable authenticated-session restart handling, first-device E2EE enrollment, durable libsignal device/prekey/Kyber material, outbound Signal session establishment, encrypted message submission, and inbound mailbox consumption/decryption.

The current Android E2EE path is:

`login → durable session → first-device enrollment → recipient device discovery → OTPK/signed-prekey claim → client-side signed-prekey + Kyber verification → libsignal SessionBuilder → durable SessionRecord → encrypted message submission → mailbox fetch → Signal PREKEY_INIT/RATCHET decryption → durable post-decrypt SessionRecord → per-message mailbox acknowledgment`.

Inbound plaintext is processed in memory only. Android does not yet provide a user-facing chat/history experience.

## Baseline

- Package/application ID: `com.samvaad.android`
- Kotlin + Jetpack Compose + Kotlin DSL
- `minSdk = 30` (Android 11)
- `compileSdk = 37`
- `targetSdk = 37`
- AGP `9.4.1`
- Kotlin `2.2.10`
- Compose BOM `2026.02.01`
- Gradle `9.6.0`
- Single `:app` module
- Verified launch on a Pixel 6a API 33 emulator

## Server integration boundary

The Android client consumes existing server contracts and does not invent Android-specific endpoints.

Current public server baseline:

`164463da10505c2b789556e02536e2f1e8701cf5`
(`feat: enforce primary and companion device roles`)

This baseline enforces server-assigned device roles: one non-revoked PRIMARY and up to four non-revoked COMPANIONS, within the five-device non-revoked limit.

The server already has E2EE device/enrollment, prekey/recovery, recipient-device discovery, OTPK claim, ciphertext transport, mailbox, history, synchronization-cursor, and device-level realtime foundations. Android currently consumes authentication, enrollment, recipient discovery, OTPK claim, ciphertext submission, mailbox fetch, and mailbox acknowledgment.

The server's durable ciphertext history is a **transition state**. The target architecture makes the Android Primary the durable history authority and uses the server as a bounded delivery/replay layer. Retention/eviction and the Primary-to-Companion history-sync protocol are not yet locked.

Field-level contracts remain in the server repository; this Android repository intentionally does not duplicate them.

## Current messaging boundary

Android currently has headless cryptographic/message-transport boundaries for both directions:

- outbound Signal encryption and ciphertext submission;
- inbound device-scoped mailbox fetch;
- inbound PREKEY_INIT/RATCHET Signal decryption;
- durable post-decrypt SessionRecord persistence before mailbox acknowledgment;
- duplicate-delivery handling through libsignal `DuplicateMessageException`;
- shared per-remote-device serialization between outbound and inbound SessionRecord mutation.

Android does **not** yet provide:

- a user-facing chat UI;
- local conversation/message persistence;
- history reads or synchronization-cursor reconciliation;
- WebSocket/STOMP integration;
- background mailbox polling;
- push notifications;
- OTPK replenishment;
- Kyber rotation;
- Companion approval/recovery UX;
- identity/fingerprint verification UI;
- Primary-owned durable conversation history;
- Primary-to-Companion history synchronization;
- encrypted backup/restore.

## Documentation map

- `docs/architecture/current-state.md` — what Android actually implements now.
- `docs/roadmap.md` — incremental Android implementation sequence.
- `docs/api/server-checkpoint.md` — server integration boundary and version reference.
- `docs/security/current-security-posture.md` — current Android security posture.
- `docs/development/setup.md` — local development baseline.
- `docs/development/testing.md` — test baseline and commands.
- `docs/adr/` — Android-only architectural decisions.
- `AGENTS.md` — implementation guardrails.

## Build / test

```bash
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

`git diff --check` must be clean before committing.
