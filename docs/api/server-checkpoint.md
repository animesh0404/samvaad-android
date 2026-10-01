# Server Checkpoint (reference only)

This repo never modifies the server and never duplicates field-level
contracts.

- Server repo: `samvaad-server` (sibling checkout, do not modify).
- Frozen checkpoint: `464e07eb7acddf7f89e18be9425ca6f87a0875a7`
  (`docs: freeze server android integration checkpoint`).
- Integration sequence source of truth:
  `samvaad-server/docs/api/android-integration-checklist.md`.
- Field-level E2EE/API detail:
  `samvaad-server/docs/api/e2ee-api.md` and `docs/api/*`.
- Product/protocol authority: `samvaad-server/docs/` + `docs/adr/`
  (especially ADR 0025 primary/companion, ADR 0018–0024 E2EE).

No Android-specific endpoints exist. When Android implements a slice, it must
consume these exact contracts without invention.
