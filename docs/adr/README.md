# Architecture Decision Records

Android-only decisions live here. Server product/protocol decisions remain in `samvaad-server/docs/adr/` and are authoritative.

Conventions: `NNNN-short-title.md` with Status / Context / Decision / Consequences. `Accepted` means decided; do not silently reopen it. Unresolved implementation questions stay out of ADRs until decided.

## Index

| ADR | Decision |
| --- | --- |
| [0001](0001-android-as-primary-device-client.md) | Android as Primary product device client |
| [0002](0002-android-build-baseline.md) | Android build baseline |

## Authority boundary

Android ADRs may define Android-specific implementation choices, but they must not redefine server protocol behavior, device-role rules, E2EE semantics, history authority, retention, or Companion synchronization contracts already governed by accepted server ADRs.
