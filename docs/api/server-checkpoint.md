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
- recipient OTPK claiming;
- ciphertext message submission;
- device-scoped mailbox fetch;
- per-message mailbox acknowledgment;
- conversation history reads;
- per-device/per-conversation synchronization-cursor reads and advancement.

For mailbox consumption, Android uses the existing `GET /api/e2ee/mailbox?limit=N` and `POST /api/e2ee/mailbox/ack` contracts. These are existing server endpoints; Android introduces no server API for Slice 8 or Slice 9.

For durable history reconciliation, Android uses the existing:

- `GET /api/e2ee/conversations/{conversationId}/messages?afterSequence=&limit=`
- `GET /api/e2ee/sync?conversationId=`
- `PUT /api/e2ee/sync`

The server validates conversation/device ownership and cursor bounds. Android treats history as reconciliation/replay input and advances the cursor only through locally contiguous durable message state.

The server remains cryptographically blind. Its durable ciphertext history remains a transition-state mechanism while the target architecture moves long-term history authority to the Android Primary.

## No server changes in Slice 9

Slice 9 required **no server implementation changes**.

The Android checkpoint `27edc0e1dfaa51b839e7d9aee06a3cc0f46825c8` consumed the existing server history/cursor contracts exactly as exposed by the public baseline above.

No Android-specific endpoint was introduced. No server retention/eviction policy, Primary succession/liveness behavior, Primary-to-Companion history-sync protocol, push contract, or backup protocol was added.

No Android client should infer future server behavior from this checkpoint.
