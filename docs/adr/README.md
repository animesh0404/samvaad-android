# Architecture Decision Records

Android-only decisions live here. Server product/protocol decisions remain in `samvaad-server/docs/adr/` and are authoritative.

Conventions: `NNNN-short-title.md` with Status / Context / Decision / Consequences. `Accepted` means decided; do not silently reopen it. Unresolved implementation questions stay out of ADRs until decided.

## Index

| ADR | Decision |
| --- | --- |
| [0001](0001-android-as-primary-device-client.md) | Android as Primary product device client |
| [0002](0002-android-build-baseline.md) | Android build baseline |
| [0003](0003-libsignal-android-feasibility-spike.md) | libsignal Android feasibility spike |
| [0004](0004-keystore-backed-crypto-vault.md) | Keystore-backed local crypto vault |
| [0005](0005-first-device-bootstrap-enrollment.md) | First-device bootstrap enrollment |
| [0006](0006-durable-refresh-token-session.md) | Durable refresh-token session |
| [0007](0007-outbound-signal-session-establishment.md) | Outbound Signal session establishment |
| [0008](0008-inbound-mailbox-consumption-and-signal-decryption.md) | Inbound mailbox consumption and Signal decryption |
| [0009](0009-durable-message-state-and-reconciliation.md) | Durable message state and history/cursor reconciliation |
| [0010](0010-companion-approval-and-recovery-ux.md) | Existing-device Companion approval and recovery UX |
| [0011](0011-primary-conversation-history-presentation.md) | Primary conversation/history presentation and behavior |
| [0026](0026-primary-to-companion-history-synchronization.md) | Primary-to-Companion history synchronization protocol (Accepted, implemented) |

## Authority boundary

Android ADRs may define Android-specific implementation choices, but they must not redefine server protocol behavior, device-role rules, E2EE semantics, history authority, retention, or Companion synchronization contracts already governed by accepted server ADRs.
