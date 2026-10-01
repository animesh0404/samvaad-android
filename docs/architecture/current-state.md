# Architecture Current State

Date: 2026-10-01.

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
  branding/title, server address input, username input, and a Continue
  action. Inputs are local Compose UI state only; Continue shows a local
  confirmation and performs no networking, authentication, persistence,
  or navigation.
- Host unit tests include Slice 1 Robolectric-based Compose UI tests
  (`EntryScreenTest`: branding, both inputs, text entry, Continue
  confirmation) alongside the generated `ExampleUnitTest` template. The
  instrumented package-name template remains. The Robolectric setup is
  test infrastructure only, not production architecture.
- The bootstrap has been verified to build and launch on a Pixel 6a API 33 emulator.

## Not implemented

The Android app currently has none of the following:

- network transport or HTTP/WebSocket integration
- authentication or session management
- device enrollment or device-role retrieval
- E2EE/Signal integration
- secure key storage / Android Keystore integration
- recovery-code handling
- local database or durable message store
- mailbox/history/cursor synchronization
- navigation between product screens
- ViewModel or dependency-injection framework
- background work
- push notifications
- Primary-to-Companion history synchronization

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
- dependency injection;
- Android Signal adapter integration;
- secure cryptographic persistence format.

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
