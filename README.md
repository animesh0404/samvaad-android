# Samvaad Android

Native Android client for Samvaad, built with Kotlin and Jetpack Compose.

Android is the **PRIMARY product device**. Web is a future COMPANION client. TUI remains parked/testing-oriented.

## Current state

Slices 0–11 are complete.

The app is a single-`:app`-module Compose application with Samvaad branding, HTTPS authentication, durable authenticated-session restart handling, first-device E2EE enrollment, durable libsignal device/prekey/Kyber material, outbound Signal session establishment, encrypted message submission, inbound mailbox consumption/decryption, durable message-state/history reconciliation, and a user-facing Primary conversation/history surface.

The current Android E2EE path is:

`login → durable session → first-device enrollment → recipient device discovery → OTPK/signed-prekey claim → client-side signed-prekey + Kyber verification → libsignal SessionBuilder → durable SessionRecord → encrypted message submission → durable outbound state → mailbox fetch → Signal PREKEY_INIT/RATCHET decryption → sealed local message state → mailbox acknowledgment → bounded history reconciliation → contiguous cursor advancement`.

Durable message state now exists locally. Message content is sealed at rest with the existing Keystore-backed wrapping-key infrastructure; Room stores message/conversation facts plus opaque/sealed BLOBs, while crypto keys and Signal SessionRecords remain in the crypto vault. Android still does not provide a user-facing chat/history experience.

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

The server already has E2EE device/enrollment, prekey/recovery, recipient-device discovery, OTPK claim, ciphertext transport, mailbox, history, synchronization-cursor, and device-level realtime foundations. Android currently consumes authentication, enrollment, recipient discovery, OTPK claim, ciphertext submission, mailbox fetch, mailbox acknowledgment, conversation history, synchronization-cursor read/write, and the existing device approval/recovery contracts. Slice 11 now presents the durable local message state through a user-facing conversation list/detail surface. Manual Sync invokes the existing bounded reconciliation sweep. There is still no scheduler, background worker, push trigger, or realtime transport.

The server's durable ciphertext history is a **transition state**. The target architecture makes the Android Primary the durable history authority and uses the server as a bounded delivery/replay layer. Retention/eviction and the Primary-to-Companion history-sync protocol are not yet locked.

Field-level contracts remain in the server repository; this Android repository intentionally does not duplicate them.

## Current messaging boundary

Android now has user-facing conversation/history presentation on top of the existing cryptographic/message-state boundaries:

- outbound Signal encryption and ciphertext submission;
- durable outbound message state with `PENDING_SEAL → SEALED → SENT` recovery;
- inbound device-scoped mailbox fetch;
- inbound PREKEY_INIT/RATCHET Signal decryption;
- sealed plaintext persistence before mailbox acknowledgment;
- duplicate-delivery handling through libsignal `DuplicateMessageException`;
- shared per-remote-device serialization between outbound and inbound SessionRecord mutation;
- bounded history ingestion from the existing server history API;
- contiguous per-conversation synchronization-cursor reconciliation;
- a deterministic, bounded reconciliation sweep covering outbox, mailbox, history, and cursors;
- a local conversation list and conversation detail view backed by Room;
- manual Sync that runs the existing bounded reconciliation sweep and reloads durable state;
- explicit friend username and recipient-device selection before sending;
- outbound send flow that reuses SessionEstablisher and MessageSender and renders the accepted durable local message;
- restart/offline rendering from the durable local message store.

Room is the durable message-state boundary. The existing Keystore-backed crypto vault remains the key/SessionRecord boundary. Room and Keystore operations are not treated as one atomic transaction; crash-recoverable state machines reconcile incomplete cross-store transitions.

Signal ciphertext alone is not treated as durable Primary history: after the Signal ratchet advances, old ciphertext cannot be assumed to remain independently decryptable indefinitely. Durable local Primary history therefore requires decrypted message content to be persisted in sealed form.

Android does **not** yet provide:

- WebSocket/STOMP integration;
- background mailbox polling;
- push notifications;
- OTPK replenishment;
- Kyber rotation;

- identity/fingerprint verification UI;
- Primary-to-Companion history synchronization;
- encrypted backup/restore;
- server retention/eviction policy;
- server-side Primary-to-Companion history-sync protocol;
- recovery-code rotation;
- automatic/polling companion approval or recovery.

Reconciliation remains a bounded operation. Slice 11 exposes it through an explicit manual Sync action; no scheduler, push trigger, background worker, or realtime subsystem has been added.

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
