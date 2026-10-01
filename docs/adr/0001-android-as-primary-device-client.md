# ADR 0001: Android as Primary Device Client

- Status: Accepted
- Date: 2026-10-01

## Context

Server ADR 0025 establishes one Primary Device and up to four Companion Devices, with the Primary as the authoritative owner of durable conversation history.

The product direction selects native Android as the first production-oriented Primary client. Web is the future Companion client and TUI development is parked/testing-oriented.

## Decision

`samvaad-android` is the Android implementation of the **Primary product device**.

This decision establishes product/device role, not a claim that the current Android code already owns durable history. The Android app must first implement the required local persistence and E2EE capabilities in later slices.

When the server exposes device records, Android consumes the server-assigned read-only `deviceRole`. Android must never infer or self-assign PRIMARY or COMPANION.

No Android-specific server endpoints are introduced by this ADR.

## Consequences

### Positive

- Android has a clear product responsibility: become the Primary history owner.
- Future Web Companion synchronization has an explicit source of authority.
- The decision aligns client development with the server's current device-role model.

### Negative

- Durable local history, secure cryptographic persistence, backup/recovery, and future Companion synchronization add complexity that is not present in the bootstrap.
- Until Primary history ownership is implemented, the server's current durable ciphertext history remains a transition-state fallback.

## Scope

Applies to Android slices. It does not define the history-sync protocol, retention policy, liveness/expiry policy, backup format, or Android implementation architecture for persistence/networking/E2EE. Those require their own decisions when implementation reaches them.
