# ADR 0005: First-Device Bootstrap Enrollment

- Status: Accepted
- Date: 2026-10-01

## Context

Slices 0–3 established authentication (in-memory `AuthSession`) and the
Keystore-backed crypto vault (ADR 0004), but no device enrollment. The
server (`164463da`) requires real public crypto material at
`POST /api/e2ee/devices`, binds the calling session on success, and
assigns all device authority server-side. The audit established the
reconcile-first rule: never regenerate identity on uncertain outcomes.

## Decision

Implement first-device bootstrap only, in one live session:

- `E2eeDeviceApi`/`HttpE2eeDeviceApi` (`HttpURLConnection` + `org.json`,
  HTTPS-only, Bearer auth, typed errors incl. `E2EE_RECOVERY_REQUIRED`
  on 403): enroll, 100-OTPK upload, owner device list.
- `EnrollmentCoordinator` (no Compose, no DI): reuse-or-generate sealed
  material exactly once, durable attempt marker before POST, reconcile
  via identity-pubkey match on uncertainty/`409`, adopt-exactly-one,
  verify server echoes, upload 100 OTPKs only when ACTIVE, transient
  25-code display with explicit ack.
- `FileDeviceMetadataStore` (non-secret JSON under `getNoBackupFilesDir`,
  schema-versioned): attempt marker + adopted-device hints + allocator
  high-water marks. Server status/role/approval truth is always re-read
  and wins on disagreement. The adopted path additionally verifies local
  keys are restorable (else fail-closed `crypto-unavailable`) and finishes
  provisioning when the server reports zero prekeys (same sealed batch).
- Local ID allocation is an Android-side documented choice (server defines
  no ranges): one-time random registration ID, monotonic per-category
  counters starting at 1, OTPK IDs never reused per device.
- Recovery codes are transient display-only: never persisted, logged, or
  vaulted. Crash-before-ack yields Active-unacked, never re-issued codes.

## Consequences

### Positive

- Single-session `login → prepare → enroll → upload → display` fits the
  verified 24h access-token lifetime with wide margin.
- Duplicate POSTs, timeout-ambiguity, and process death all converge via
  reconcile-first; `409` is a reconcile trigger, never success.
- PENDING responses stop safely with no upload and no invented approval UI.

### Negative

- Death between enroll-commit and OTPK upload strands the device on a
  dead session (no rebind API exists); recovery costs a recovery code via
  `bind`. Documented, not solved here.
- Adopted-but-unacked devices show an honest warning; code rotation is a
  later slice.

## Scope

First bootstrap only. Companion approval, recovery enrollment/entry/
rotation, revocation, messaging, auth persistence, Room, and release
work remain explicitly out of scope.
