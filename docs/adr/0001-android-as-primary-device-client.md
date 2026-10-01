# ADR 0001: Android as Primary Device Client

- Status: Accepted
- Date: 2026-10-01

## Context

Server ADR 0025 establishes Primary/Companion device authority with
device-owned history. The product direction (server roadmap, TUI parked,
e2ee-lib MessageStore parked) names Android as the PRIMARY device and Web as
a future COMPANION.

## Decision

`samvaad-android` is the PRIMARY-device client. It will eventually own
durable Primary history locally; until that slice exists, the server’s
durable per-device history is the fallback (per the frozen integration
checklist).

Android consumes the same E2EE contracts as every other client. No
Android-specific endpoints will be invented.

## Consequences

### Positive

- Single primary-history owner aligns with server authority model.
- Companion (Web) history-sync has a defined future source.

### Negative

- Primary responsibilities (durable store, backup/restore, sync source)
  arrive as future complexity; not in bootstrap.

## Scope

Applies to all Android slices. Any local state must be justified as
client/session/presentation state until the durable Primary store slice is
explicitly scheduled. Never infer primaryship — always read `deviceRole`
from the server when devices exist.
