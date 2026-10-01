# Samvaad Android agent guidance

## Design authority

- Android is the **PRIMARY product client**. Web is a future COMPANION. TUI is parked/testing-oriented.
- Durable product and protocol decisions live in the server repository's accepted ADRs and API contracts. Android ADRs record Android-specific decisions only and must not contradict them.
- The current public server baseline relevant to Android is `164463da10505c2b789556e02536e2f1e8701cf5` (`feat: enforce primary and companion device roles`).
- The Android bootstrap previously referenced `464e07eb7acddf7f89e18be9425ca6f87a0875a7` as a frozen checkpoint. That SHA is not reachable from the current public server `main` history, so do not present it as the current public checkpoint.
- Do not invent or change server APIs from the Android client. Consume the actual server contracts when an implementation slice reaches them.
- `samvaad-server/docs/api/e2ee-api.md` and accepted server ADRs, especially ADR 0025, are authoritative for the currently exposed E2EE/device architecture.

## Incremental process

1. Implement only the current small slice.
2. Keep the project buildable and runnable after every slice.
3. Prefer simple, idiomatic Android code. No premature production architecture.
4. The developer is new to native Android — keep diffs reviewable and introduce concepts only when the slice requires them.

## Guardrails

- Keep the app buildable after every slice.
- Do not add networking, authentication, device enrollment, E2EE/Signal, database/message storage, navigation, ViewModel, DI, background work, push notifications, or history sync until the roadmap explicitly reaches those concerns.
- Keep API DTOs, domain state, and persistence separate when they arrive. Do not add fake encryption abstractions.
- Never persist or log secrets.
- Do not commit build outputs or machine-local files (`build/`, `.gradle/`, `local.properties`, `.idea/`, `.kotlin/`).
- Do not commit or push unless explicitly instructed.
- Run `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`, and `git diff --check` before a commit.

## Architecture boundary

Android is designated as the Primary device client, but Primary-owned durable history is **not implemented yet**. Do not treat the designation as proof that Android currently owns chat history.

The server currently provides E2EE device/enrollment, ciphertext transport, mailbox, history, cursor, and realtime foundations. Server durable ciphertext history is a transition state. The target direction moves long-term history authority to the Primary and makes the server a bounded delivery/replay layer; exact retention/eviction and Primary-to-Companion history-sync protocol are not yet locked.

When a future slice requires a decision that is not already locked, stop and surface it rather than inventing a contract.
