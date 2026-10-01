# Testing

## What exists

- `app/src/test/.../EntryScreenTest.kt`: Slice 1 Robolectric-based Compose
  UI tests for observable entry-screen behavior (branding, inputs,
  text entry), extended in Slice 2 with a fake `AuthApi` boundary:
  empty/invalid submission issues no request, request shape
  (server/identifier/password/`ANDROID`), success/failure UI, token and
  password non-rendering, and duplicate-submit prevention. Slice 3 adds
  transition coverage: success reaches the home surface with the
  identifier, failure stays on the entry form. No live server
  required. Test infrastructure only, not production architecture.
- `app/src/test/.../ExampleUnitTest.kt`: template host test
  (`assertEquals(4, 2 + 2)`).
- `app/src/androidTest/.../ExampleInstrumentedTest.kt`: template package-name
  check. Requires device/emulator; not part of the slice gate.

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

## Commands (run from repo root)

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
git diff --check
```

Slice gate is `assembleDebug` + `testDebugUnitTest` + `diff --check`.
Instrumented tests are manual (emulator) until a slice needs them.

## Policy

- Add or update tests only when a slice adds behavior.
- Keep tests deterministic, host-side where possible.
- Do not introduce test frameworks without a slice requirement.
