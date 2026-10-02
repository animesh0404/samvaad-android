# Server Integration Boundary

This document records the Android client's server reference without duplicating the server's field-level contracts.

## Current public server baseline

Repository: `animesh0404/samvaad-server`

Current relevant public `main` commit:

`164463da10505c2b789556e02536e2f1e8701cf5`

Commit message:

`feat: enforce primary and companion device roles`

This is the current public server baseline relevant to Android integration. It establishes server-assigned Primary/Companion roles while preserving the existing E2EE enrollment, approval, revocation, transport, mailbox, history, cursor, and realtime foundations.

## Important historical reference

The Android bootstrap previously recorded:

`464e07eb7acddf7f89e18be9425ca6f87a0875a7`

as a "frozen server Android integration checkpoint". That SHA is not reachable from the current public server `main` history, so this repository no longer treats it as the public integration baseline.

If that commit remains in an unpublished local server checkout, it is historical/local context only. It must not be used as a reason to invent an Android API.

## Contract authority

Android does not duplicate field-level server contracts.

For future integration work, consult the actual server repository at the relevant implementation point, especially:

- `docs/api/e2ee-api.md` for E2EE device, prekey, mailbox, history, cursor, and realtime contracts;
- accepted server ADRs, especially ADR 0025 for Primary/Companion authority and history ownership;
- the server's current authentication and user/friend API contract documents for those respective slices.

The previously referenced `docs/api/android-integration-checklist.md` is not currently present on public server `main`; do not treat that path as a remotely available source of truth.

## Current server/client boundary

Android currently consumes existing server contracts for:

- authentication and refresh/logout;
- first-device E2EE enrollment and initial OTPK upload;
- recipient device discovery;
- recipient OTPK claiming.

Android has not yet integrated the server's ciphertext message submission, mailbox, history/cursor, or realtime delivery surfaces.

The server remains cryptographically blind. The current server-side durable ciphertext history is a transition-state mechanism, while the target architecture moves long-term history authority to the Android Primary.

No Android-specific server endpoints are authorized by this document.
