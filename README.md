# Samvaad Android

Native Android client for Samvaad, built with Kotlin and Jetpack Compose.

Android is the **PRIMARY product device**. Web is a future COMPANION client. TUI remains parked/testing-oriented.

## Current state

Slice 0 (repository bootstrap), Slice 1 (basic Samvaad entry UI), and Slice 2 (authentication boundary) are complete. The app is a single-`:app`-module Compose application showing the Samvaad entry screen: branding/title, server address, username, and password inputs, and a Continue action backed by local UI state. Continue performs a real `POST /api/auth/login` with `clientPlatform: "ANDROID"` and keeps the returned access/refresh tokens and sessionId only in an in-memory session; a minimal "Signed in as …" state proves success.

No Samvaad device enrollment, E2EE, local message storage, navigation, ViewModel, DI, background work, push, history synchronization, persistent credentials, or automatic token refresh has been implemented yet.

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

The server already has E2EE device/enrollment, prekey/recovery, ciphertext transport, mailbox, history, synchronization-cursor, and device-level realtime foundations. Android has not integrated them yet.

The server's durable ciphertext history is a **transition state**. The target architecture makes the Android Primary the durable history authority and uses the server as a bounded delivery/replay layer. Retention/eviction and the Primary-to-Companion history-sync protocol are not yet locked.

Field-level contracts remain in the server repository; this Android repository intentionally does not duplicate them.

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
