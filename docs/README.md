# Samvaad Android Documentation

This documentation distinguishes **implemented**, **planned**, **deferred**, and **unknown** state. Planned or target architecture must not be read as implemented behavior.

- [Architecture Current State](architecture/current-state.md) — what Android actually implements today.
- [Android Roadmap](roadmap.md) — the incremental implementation sequence.
- [Server Integration Boundary](api/server-checkpoint.md) — the server baseline and Android integration boundary; field-level contracts remain in the server repository.
- [Development Setup](development/setup.md) — toolchain and run instructions.
- [Testing](development/testing.md) — current test baseline and commands.
- [Security Posture](security/current-security-posture.md) — current Android security state and future boundaries.
- [ADRs](adr/) — Android-only decisions.

## Authority

The server repository remains authoritative for product/protocol decisions and server contracts. Accepted server ADR 0025 defines the Primary/Companion architecture and current server API documentation defines the E2EE/device transport surface.

If Android documentation conflicts with the implemented server or an accepted server ADR, reconcile the conflict before client implementation continues.
