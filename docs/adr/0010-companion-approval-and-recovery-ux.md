# ADR 0010 — Existing-device Companion approval and recovery UX

**Status:** Accepted

## Context

The server already defines device enrollment, pending Companion approval, revocation-as-denial, recovery enrollment, and recovery binding. Android needs a bounded user-facing state/UX layer for those existing contracts without redefining server role rules or introducing new persistence or server APIs.

The server remains authoritative for device status and role. Recovery codes are sensitive one-shot credentials and must not become durable Android state.

## Decision

Android implements the existing approval and recovery contracts as follows:

1. **Manual authoritative status.** Pending, denied, active, and recovery-required states are converged by querying the existing device-list contract. Android does not poll, add push, or invent a new status endpoint.
2. **Approval by an active bound device.** An ACTIVE-bound Android installation may review pending devices and call the existing approval endpoint. Pending or unbound installations do not expose approval controls. There is no Android-side approval policy beyond the server's authorization.
3. **Denial is server revocation.** Android does not invent a reject endpoint. A pending device that becomes revoked converges to a distinct denied UI state, from which the user may explicitly start a fresh enrollment.
4. **Two recovery paths.** A transient recovery code may be used either to bind the session to an existing ACTIVE device or to recover-enroll a new device. These are explicit user choices.
5. **Bind carries no private keys.** The existing bind contract accepts only the recovery code and device identifier. Android therefore allows an adopted device record to have nullable local crypto handles.
6. **Handle-less binding is valid but crypto-incomplete.** A successfully bound installation without local private key/SessionRecord handles is shown as Device bound, not as fully messaging-ready. Existing messaging paths continue to fail closed when local crypto material is unavailable. Recover-enroll-new-device is the route to create local messaging material.
7. **Recovery codes are transient.** Recovery codes live only in UI/operation memory, are cleared after attempts and when leaving the recovery surface, and are never written to metadata, Room, the crypto vault, or logs.
8. **No rotation in this slice.** Recovery-code rotation remains deferred.
9. **No new persistence architecture.** Slice 10 reuses the existing device metadata, crypto vault, and auth session boundaries. No Room/DataStore/SharedPreferences addition is required.

## Consequences

- Android can represent the complete server-defined pending/approval/recovery UX without duplicating server role authority.
- A bind-only installation can be server-authenticated and bound while remaining unable to send/decrypt messages locally; the UI explicitly communicates that limitation.
- Recovery can be retried by explicit user action without persisting recovery credentials.
- Approval/recovery remains a bounded foreground capability; background polling, push, realtime, Primary-gated approval, succession, and liveness are not introduced.
- The future Primary-to-Companion history protocol remains independent of this slice.
- Recovery-code rotation and broader device-management UX remain future work.