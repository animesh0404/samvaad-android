# ADR 0011 — Primary conversation/history presentation and behavior

## Status

Accepted.

## Context

Slice 9 established Room-backed durable message state, sealed message content, server-history reconciliation, and contiguous synchronization cursors. Slice 10 established the device approval/recovery UX. The Android Primary now needs a user-facing surface that presents the durable local history and exercises the existing send/reconciliation boundaries without prematurely defining realtime delivery or the future Companion history-sync protocol.

The server already provides the history, cursor, recipient-directory, session-establishment, and ciphertext-submission contracts required by this surface. No new Android-specific server endpoint is required.

## Decision

Slice 11 uses the existing durable local message state as the presentation source of truth.

- The authenticated Home surface presents a conversation list derived from known durable Room conversation state.
- Conversation detail renders durable messages in sequence order.
- MessageContentSealer is reused to open sealed message content only in memory for presentation.
- A local Compose state switch plus BackHandler is used for list/detail navigation. No Navigation Compose, ViewModel, DI framework, or repository/use-case layer is introduced by this slice.
- Manual Sync invokes the existing bounded ReconciliationSweep and reloads Room state. Sync is not scheduled or run in the background.
- Sending requires an explicit friend username and explicit recipient-device selection, then reuses SessionEstablisher and MessageSender.
- The UI exposes safe loading/error/sending states and never exposes ciphertext, tokens, keys, or other cryptographic material.
- An installation with no local crypto handles remains Device bound and does not expose messaging UI; existing fail-closed messaging guards remain the actual capability boundary.
- Restart/offline presentation reads durable Room state without requiring a network call.

This ADR does not define realtime, push, server retention, backup/restore, or Primary-to-Companion history synchronization.

## Consequences

Positive:
- The Primary can present durable conversation history immediately from local state.
- Existing cryptographic and delivery invariants remain centralized in SessionEstablisher, MessageSender, InboxProcessor, ReconciliationSweep, Room, and the Keystore-backed content sealer.
- Restart/offline behavior is testable without adding a new persistence architecture.
- Manual reconciliation provides a deterministic bridge until a later realtime/background mechanism is designed.

Constraints:
- New messages do not arrive automatically; the user must use the existing manual Sync path for reconciliation.
- The current conversation list is derived from locally known durable conversations rather than a new server-side conversation-list protocol.
- Large-history pagination and richer conversation metadata are not finalized here.
- Companion history synchronization remains deferred until its protocol is defined.
