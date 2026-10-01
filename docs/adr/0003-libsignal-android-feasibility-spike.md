# ADR 0003: libsignal Android Feasibility Spike

- Status: Accepted (spike executed 2026-10-01; local-only, not a product decision)
- Date: 2026-10-01

## Context

Enrollment (`POST /api/e2ee/devices` at server baseline `164463da`)
requires real libsignal-produced public material (identity, signed prekey +
signature, Kyber triple, OTPKs). Android had no crypto producer. Before any
enrollment slice, we had to prove the aligned libsignal version runs on our
devices and produces server-compatible material.

## Decision

Run a local-only spike on `org.signal:libsignal-android:0.86.5` +
`org.signal:libsignal-client:0.86.5` (exact aligned pair with
server/e2ee-lib), behind a minimal `AndroidSignalAdapter` that isolates all
`org.signal.libsignal.*` imports. Private material stays in memory only:
no persistence, no Keystore, no network, no UI.

Build note: the Signal artifact requires core-library desugaring, so the
app enables `isCoreLibraryDesugaringEnabled` with
`com.android.tools:desugar_jdk_libs:2.1.5` and excludes desktop natives
(`libsignal_jni*.dylib`, `signal_jni*.dll`) from packaging.

## Result

Proven on both targets (instrumented test
`CryptoSpikeInstrumentedTest`, plus host JVM `CryptoSpikeUnitTest`):

- Pixel_6a API 33 x86_64 emulator: PASS
- Physical Pixel 6a (arm64-v8a, device Android 17): PASS
- 1 identity (33 B `0x05‖X25519`), 1 signed prekey + 64 B signature,
  1 Kyber-1024 triple (1569 B + 64 B signature), 5 OTPKs — all parsed and
  signature-verified through libsignal APIs themselves, standard-Base64
  round-tripped, in-memory enrollment shape built but never sent.

## Consequences

### Still outstanding (not decided by this spike)

- AGPL-3.0-only distribution decision for any shipped Android artifact.
- Production ID allocation, 100-OTPK batch, replenishment, session/messaging.
- Keystore/vault and durable store design (no persistence exists yet).
- Enrollment state machine and UI (explicitly not started).

### Negative

- App now links AGPL code even for local builds; release/distribution
  remains blocked on the licensing decision above.
- Desugaring + native `.so` per ABI increase build complexity/APK size;
  acceptable for now, to be measured when packaging matters.
