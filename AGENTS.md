# Samvaad Android agent guidance

## Design authority

- Server is frozen at `464e07eb7acddf7f89e18be9425ca6f87a0875a7`. Do not modify
  the server. Do not invent or change server APIs.
- Server contract source of truth:
  `samvaad-server/docs/api/android-integration-checklist.md` plus
  `docs/api/e2ee-api.md`. This repo does not duplicate field-level contracts;
  see `docs/api/server-checkpoint.md`.
- Durable product decisions live in the server repo (`docs/`, `docs/adr/`).
  Android ADRs in `docs/adr/` record Android-only decisions and must not
  contradict LOCKED server decisions. Surface conflicts instead of working
  around them.

## Incremental process

1. Implement only the current small slice.
2. Keep the project buildable and runnable after every slice.
3. Prefer simple, idiomatic Android code. No premature production architecture.
4. The developer is new to native Android — keep diffs reviewable, do not
   introduce frameworks unless the slice requires them.

## Guardrails

- Keep the generated Compose UI working. No architectural changes without an
  explicit slice.
- Do NOT add: networking, authentication, device enrollment, E2EE / Signal,
  database / message store, navigation, ViewModel, DI, background work, push
  notifications, history sync — until a roadmap slice explicitly asks for them.
- Keep API DTOs / domain / persistence separate when they arrive. Do not add
  fake encryption abstractions.
- Never persist or log secrets. No credentials exist in this repo yet — keep
  it that way.
- Do not commit build outputs or machine-local files (`build/`, `.gradle/`,
  `local.properties`, `.idea/`, `.kotlin/`).
- Do not commit or push unless explicitly instructed.
- Run `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`,
  and `git diff --check` before requesting a commit.
