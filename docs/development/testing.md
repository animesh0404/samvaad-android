# Testing

## What exists

- `app/src/test/.../EntryScreenTest.kt`: Slice 1 Robolectric Compose UI tests, extended through authentication/session boundaries.
- `app/src/test/.../EnrollmentCoordinatorTest.kt`: first-device bootstrap reconciliation, generation/reuse, marker ordering, OTPK provisioning, recovery-code acknowledgment, no-regeneration, and fail-closed tests.
- `app/src/test/.../HttpE2eeDeviceApiTest.kt`: enrollment/prekey transport tests using `ServerSocket` stubs.
- `app/src/test/.../CryptoVaultUnitTest.kt`, `DeviceMetadataStoreTest.kt`, `PrekeyIdAllocatorTest.kt`: crypto envelope/AAD, corruption/isolation/no-plaintext, metadata, and allocator coverage.
- `app/src/test/.../SessionStoreTest.kt`, `SessionRefresherTest.kt`, `AuthRefreshLogoutTest.kt`, `SessionGateTest.kt`: durable auth-session recovery/rotation/rejection/logout and root-gate coverage.
- `app/src/test/.../SessionCryptoTest.kt`: real libsignal outbound session construction, signature verification, TOFU behavior, SessionRecord readiness, and encryption coverage.
- `app/src/test/.../HttpSessionDirectoryApiTest.kt`: recipient-directory and OTPK-claim HTTP contract tests.
- `app/src/test/.../SessionEstablisherTest.kt`: reuse-first behavior, explicit device selection, claim-burn semantics, fresh-requestId retry, single-flight concurrency, durable metadata/blob consistency, AAD isolation, and identity pinning.
- `app/src/test/.../SessionDecryptTest.kt`: real libsignal PREKEY_INIT/RATCHET inbound decryption, identity pinning, malformed/unsupported input, duplicate handling, sender-chain installation, and Kyber replay behavior.
- `app/src/test/.../HttpInboxApiTest.kt`: mailbox GET/ACK HTTP contract tests, authentication/error classification, malformed responses, limit validation, and exact ACK request shape.
- `app/src/test/.../InboxProcessorTest.kt`: mailbox processing, session lookup, decrypt/seal/ACK ordering, failure/redelivery behavior, unknown senders, duplicate acknowledgment, and same-device/cross-direction concurrency.
- `app/src/test/.../MessageContentSealerTest.kt`: sealed message-content envelope/AAD, round-trip, corruption, wrong-message isolation, and no-plaintext-at-rest assertions.
- `app/src/test/.../MessageDaoTest.kt`: message deduplication, state transitions, history queries, ACK state, request-ID uniqueness, server-message identity, and highest-contiguous sequence calculation.
- `app/src/test/.../MessageDatabaseTest.kt`: Room database placement/schema bootstrap and fresh-install behavior.
- `app/src/test/.../HttpHistoryApiTest.kt`: history/cursor endpoint validation, serialization, malformed responses, and server error classification.
- `app/src/test/.../MessageSenderTest.kt` and Slice 9 sender coverage: durable outbound state transitions, exact replay, failure windows, server acceptance metadata, and recovery.
- `app/src/test/.../InboxProcessorTest.kt` and Slice 9 inbound coverage: durable message insertion, ACK ordering, duplicate convergence, cursor gaps, and shared-lock behavior.
- `app/src/test/.../ReconciliationSweepTest.kt`: bounded outbox/mailbox/history/cursor reconciliation, idempotent re-entry, cursor conflict handling, sequence gaps, malformed history, and transport-failure recovery.
- `app/src/androidTest/.../SignalSessionRestartInstrumentedTest.kt`: real Android libsignal + Keystore-backed outbound SessionRecord persistence and restart recovery.
- `app/src/androidTest/.../InboxRestartInstrumentedTest.kt`: real Android libsignal inbound PREKEY/RATCHET continuity, Keystore-backed SessionRecord persistence, process-death recovery, duplicate-after-restart behavior, and durable message-row recovery.
- `app/src/androidTest/.../SweepRestartInstrumentedTest.kt`: real Room + Keystore + libsignal restart/reconciliation proof across process restart.
- `app/src/androidTest/.../CryptoVaultInstrumentedTest.kt`, `CryptoVaultRestartInstrumentedTest.kt`: Keystore round-trip and fail-closed corruption/missing-key behavior.
- `app/src/androidTest/.../SessionStoreInstrumentedTest.kt`, `SessionRestartInstrumentedTest.kt`: durable auth-session recovery.
- `app/src/androidTest/.../ExampleInstrumentedTest.kt`: template package-name check.

## Slice verification history

### Slice 6

The Slice 6 implementation was committed as `1f935d2`.

- Host unit suite: `164/164` pass.
- Slice 6 instrumented class: `5/5` pass on the API 33 emulator.
- Force-stop two-phase restart recovery passed on the API 33 emulator.
- The same restart/recovery proof, including encryption after restoration, was previously completed on the physical Pixel 6a (arm64, API 37).
- Debug and Android-test APK builds succeeded offline.
- `git diff --check` was clean before commit.

The existing `CryptoVaultInstrumentedTest` has a pre-existing exact-count assertion that can be state-sensitive across repeated installs; fresh-state runs are the expected test condition.

### Slice 7

The outbound encrypted-message submission implementation was committed as `7013e7e`.

- Host unit suite: `197/197` pass.
- Debug and Android-test APK builds succeeded.
- Restart proof covered post-encrypt SessionRecord persistence and continued ratchet use on the emulator and physical Pixel 6a.
- Message submission tests cover exact envelope serialization, status/error classification, retry identity, and per-remote-device serialization.

### Slice 8

The inbound mailbox/decryption implementation was committed as `aa1f4f1`.

- Host unit suite: `237/237` pass.
- Fresh API 33 emulator instrumented suite: `27/27` pass, including the three Slice 8 inbox tests.
- Restart proof passed through adb-separated seal → force-stop → recover on the API 33 emulator and the physical Pixel 6a.
- Repeat-recovery/idempotency exercised the duplicate path on both devices.
- Debug and Android-test APK builds succeeded offline.
- `git diff --check` was clean before commit.
- No live server is required by the automated test suites.

### Slice 9

The durable message-state and reconciliation implementation was committed as `27edc0e`.

- Host unit suite: `313/313` pass with `--rerun-tasks`.
- Debug APK build succeeded.
- Android-test APK build succeeded.
- Fresh API 33 emulator instrumented suite: `29/29` pass after clearing stale application data.
- Physical Pixel 6a instrumented suite: `29/29` pass.
- Restart/recovery coverage exercised Room, Keystore, and real libsignal state across process-death boundaries.
- Reconciliation coverage exercised durable outbox replay, inbound duplicate convergence, history ingestion, sequence gaps, cursor conflict handling, and cursor transport recovery.
- `git diff --check` was clean before the checkpoint commit.
- The checkpoint contains no documentation changes and no server changes.
- The public server baseline remained `164463da10505c2b789556e02536e2f1e8701cf5`.

The earlier exact-count failure observed during the Slice 9 instrumented work was caused by stale app data. The app data was cleared, the same test was rerun without weakening the assertion, and the full emulator and physical suites passed.

## Commands

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
./gradlew :app:assembleDebugAndroidTest
git diff --check
```

For native/Keystore/Room slices, run the relevant instrumented tests on the Pixel 6a API 33 x86_64 emulator and, when available, the physical Pixel 6a.

## Policy

- Add or update tests when a slice adds behavior.
- Keep tests deterministic, host-side where possible.
- Use fresh app state for tests that assert exact persistent-vault/database counts.
- Do not introduce test frameworks without a slice requirement.
