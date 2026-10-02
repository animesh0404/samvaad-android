# ADR 0007 — Outbound Signal Session Establishment

- Status: Accepted
- Date: 2026-10-02

## Context

The Android client now has an authenticated, enrolled local E2EE device with durable libsignal identity/prekey/Kyber material. The server already exposes friendship-gated recipient-device discovery and atomic OTPK claiming. The next required boundary is establishing a durable outbound libsignal session with another ACTIVE device without adding message transport yet.

The server remains cryptographically blind. The Android client must validate the public bundle locally before giving it to libsignal.

## Decision

### 1. Android V1 Signal address

Android constructs:

`SignalProtocolAddress(remoteUsername, remoteSignalDeviceId)`.

The server `deviceId` remains the durable application/routing identity and is stored alongside the Signal address metadata.

The remote session metadata pins:

- server `deviceId`;
- remote username;
- remote `signalDeviceId`;
- remote registration ID;
- remote identity public key.

The current Android recipient-device contract does not expose the remote user's UUID, so Android does not claim cross-client Signal-address interoperability with the existing TUI UUID-based address convention in this slice. A username change is treated as a session miss/re-establishment condition, never as silent migration.

### 2. Recipient selection

The caller must provide an explicit remote `deviceId`. Directory results are never auto-selected or fanned out across multiple ACTIVE devices.

The existing server directory and OTPK-claim contracts are consumed as-is; no Android-specific server endpoint is introduced.

### 3. Cryptographic validation

Before `SessionBuilder.process()`, Android:

1. parses the recipient identity, signed-prekey, and Kyber public material through libsignal;
2. verifies the signed-prekey signature against the recipient identity;
3. verifies the Kyber signature against the recipient identity;
4. rejects missing Kyber material for this establishment path;
5. constructs the Kyber-mandatory `PreKeyBundle`.

If an OTPK is unavailable, the bundle uses libsignal's `NULL_PRE_KEY_ID` and a null OTPK public key, preserving the server's signed-prekey fallback.

### 4. Session readiness and persistence

The session is established through libsignal `SessionBuilder.process()`. Readiness requires `SessionRecord.hasSenderChain()`.

The canonical `SessionRecord.serialize()` bytes are sealed with the existing Android Keystore-backed vault using:

- `CryptoRecordKind.SESSION = 0x05`;
- a separate `signal-sessions/` no-backup namespace;
- a deterministic handle derived from `"samvaad-signal-session-v1:" + remoteDeviceId` via Java `UUID.nameUUIDFromBytes()`.

Remote-session metadata is stored separately in `signal-sessions/sessions.json` using atomic temporary-file replacement.

A valid metadata+blob pair is reusable without another network claim or `SessionBuilder.process()`.

### 5. Local identity authority

Session establishment always restores the already-adopted local identity from the existing device metadata and Keystore-backed vault.

This slice never generates a replacement local identity.

### 6. Identity trust scope

This slice implements pin-and-fail-closed TOFU:

- first verified remote identity is pinned;
- the same identity is accepted on reuse;
- a changed identity fails closed.

Fingerprint display, explicit verification, trust-state transitions, and identity-change UX are deferred.

### 7. OTPK claim and retry semantics

Every new OTPK claim uses a fresh UUID request ID.

A claim response is not cached for later reuse. If establishment fails after a claim response is received, the client treats that OTPK as consumed and the next attempt makes a fresh claim with a fresh request ID.

A claim conflict gets one bounded retry with a new request ID. There is no recursive retry loop.

The request ID is attempt-local and is not persisted as session authority.

### 8. Failure atomicity

The session blob is sealed only after successful libsignal establishment and readiness validation. Metadata is written only after the blob is sealed.

An orphaned blob without metadata is never used as an established session. Metadata without a usable blob fails closed. Identity mismatch fails closed. Neither condition regenerates local identity.

### 9. Scope

This ADR covers outbound session establishment only.

It does not define:

- message submission;
- inbound decryption;
- mailbox/history synchronization;
- WebSocket/STOMP;
- OTPK replenishment;
- Kyber rotation;
- Companion approval/recovery UX;
- identity verification UI;
- backup/restore;
- Primary-owned history;
- Primary-to-Companion history synchronization.

Those require their own implementation decisions where not already governed by server ADRs.

## Consequences

Android now has a durable cryptographic session boundary that can be used by a later encrypted-message transport slice.

The server remains unaware of Signal session state.

A failed post-claim establishment can burn an OTPK, so later UI/orchestration must not introduce automatic retry loops that reuse claimed bundles.

Android-to-TUI session interoperability is not claimed by this decision because the current Android directory contract does not expose the user UUID used by the TUI Signal address convention.

The libsignal AGPL-3.0-only distribution decision remains outstanding and is not resolved by this ADR.
