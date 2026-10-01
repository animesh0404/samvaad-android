# Android Roadmap

Slice discipline: one small reviewable slice at a time. The developer is new
to native Android; do not bundle unrelated learning goals.

## Slice 0 — Repository bootstrap: DONE

- Generated Compose baseline + “Hello Samvaad!” + this `docs/` foundation.
- First commit. No features.

## Next candidate slices (PLANNED, in order, none started)

1. UI hygiene (no behavior change): align `GreetingPreview` param, extract
   greeting if useful, keep same rendered output.
2. Compose learning slice: string resources / theme reading — still no
   navigation, ViewModel, or persistence.
3. Development hardening: document emulator + unit-test workflow from real
   runs (no new features).

## Explicitly deferred (do not schedule without a decision)

- Networking / HTTP client choice.
- Authentication (login / `clientPlatform: "ANDROID"` / token handling).
- Device enrollment, recovery codes, prekeys, Kyber material.
- E2EE / Signal integration, mailbox/history/cursor, realtime WebSocket.
- Database / `MessageStore` / local history.
- Navigation, ViewModel, DI, background work, push notifications.
- History sync (Primary → Companion protocol).

Each deferred item waits on its roadmap slice and on the frozen server
contracts in `docs/api/server-checkpoint.md`.
