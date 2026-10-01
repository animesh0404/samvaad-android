# Testing

## What exists

- `app/src/test/.../ExampleUnitTest.kt`: template host test
  (`assertEquals(4, 2 + 2)`). No Samvaad logic covered.
- `app/src/androidTest/.../ExampleInstrumentedTest.kt`: template package-name
  check. Requires device/emulator; not part of the bootstrap gate.

## Commands (run from repo root)

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
git diff --check
```

Bootstrap gate is `assembleDebug` + `testDebugUnitTest` + `diff --check`.
Instrumented tests are manual (emulator) until a slice needs them.

## Policy

- Add or update tests only when a slice adds behavior.
- Keep tests deterministic, host-side where possible.
- Do not introduce test frameworks without a slice requirement.
