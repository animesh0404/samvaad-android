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

## Next

### Slice 1 — Basic Samvaad entry UI

PLANNED.

A UI-only slice:

- Samvaad branding/title;
- server address input;
- username input;
- Continue action;
- local UI state only;
- no networking;
- no authentication;
- no persistence;
- no navigation;
- no E2EE.

The purpose is to establish the basic Compose state/recomposition mental model and replace the generated greeting with the first Samvaad-specific screen.

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
