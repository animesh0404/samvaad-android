# Testing

## What exists

- `app/src/test/.../EntryScreenTest.kt`: Slice 1 Robolectric-based Compose UI tests for observable entry-screen behavior, extended through authentication/session slices.
- `app/src/test/.../EnrollmentCoordinatorTest.kt`: first-device bootstrap reconciliation, generation/reuse, marker ordering, OTPK provisioning, recovery-code acknowledgment, no-regeneration, and fail-closed tests.
- `app/src/test/.../HttpE2eeDeviceApiTest.kt`: enrollment/prekey transport tests using `ServerSocket` stubs.
- `app/src/test/.../CryptoVaultUnitTest.kt`, `DeviceMetadataStoreTest.kt`, `PrekeyIdAllocatorTest.kt`: crypto envelope/AAD, corruption/isolation/no-plaintext, metadata, and allocator coverage.
- `app/src/test/.../SessionStoreTest.kt`, `SessionRefresherTest.kt`, `AuthRefreshLogoutTest.kt`, `SessionGateTest.kt`: durable auth-session restore/rotation/rejection/logout and root-gate coverage.
- `app/src/test/.../SessionCryptoTest.kt`: real libsignal outbound session construction, signature verification, TOFU behavior, SessionRecord readiness, and encrypt-probe coverage.
- `app/src/test/.../HttpSessionDirectoryApiTest.kt`: recipient-directory and OTPK-claim HTTP contract tests including authorization/status/error parsing, fallback responses, request IDs, malformed protocol responses, and HTTPS enforcement.
- `app/src/test/.../SessionEstablisherTest.kt`: reuse-first behavior, explicit device selection, claim-burn semantics, fresh-requestId retry, single-flight concurrency, durable metadata/blob consistency, AAD isolation, and identity pinning.
- `app/src/androidTest/.../CryptoVaultInstrumentedTest.kt`, `CryptoVaultRestartInstrumentedTest.kt`: Keystore round-trip, fail-closed corruption/missing-key, force-stop and physical-reboot recovery.
- `app/src/androidTest/.../SessionStoreInstrumentedTest.kt`, `SessionRestartInstrumentedTest.kt`: durable auth-session recovery.
- `app/src/androidTest/.../SignalSessionRestartInstrumentedTest.kt`: real Android libsignal + Keystore-backed SessionRecord persistence, corrupt/missing-state fail-closed behavior, no-plaintext scan, force-stop recovery, and encryption after restoration.
- `app/src/androidTest/.../ExampleInstrumentedTest.kt`: template package-name check.

## Current Slice 6 verification

The Slice 6 implementation was committed as `1f935d2` and verified before push.

- Host unit suite: `164/164` pass.
- Slice 6 instrumented class: `5/5` pass on the API 33 emulator.
- Force-stop two-phase restart recovery: passed on the API 33 emulator.
- The same restart/recovery proof, including encryption after restoration, was previously completed on the physical Pixel 6a (arm64, API 37).
- Debug and Android-test APK builds succeeded offline.
- `git diff --check` was clean before commit.
- No live server is required by the automated test suites.

The existing `CryptoVaultInstrumentedTest` has a pre-existing exact-count assertion that can be state-sensitive across repeated installs; fresh-state runs are the expected test condition. This is separate from Slice 6 logic.

## Test-only harness notes (Slice 1)

- `testImplementation` adds Robolectric `4.17` and Compose `ui-test-junit4`
  (BOM-managed) for host UI tests only.
- `testOptions.unitTests.isIncludeAndroidResources = true` wires the merged
  manifest/resources into host tests.
- Unit-test tasks run on a JDK 21 toolchain with
  `--add-opens=java.base/jdk.internal.access=ALL-UNNAMED` (Robolectric 4.17
  cannot run on JDK 25).
- `EntryScreenTest` pins `@Config(sdk = [36])`: the Compose BOM's
  espresso-idling-resource calls the hidden `InputManager.getInstance()`,
  which is absent from Robolectric's SDK 37 runtime jar.

## Commands

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
./gradlew :app:assembleDebugAndroidTest
git diff --check
```

For native/Keystore slices, run the relevant instrumented tests on the Pixel 6a API 33 x86_64 emulator and, when available, the physical Pixel 6a.

## Policy

- Add or update tests only when a slice adds behavior.
- Keep tests deterministic, host-side where possible.
- Do not introduce test frameworks without a slice requirement.
