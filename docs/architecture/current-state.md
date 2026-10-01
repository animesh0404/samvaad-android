# Architecture Current State

Date: 2026-10-01. Baseline: Android Studio-generated project + manual
“Hello Samvaad!” text change. Verified to launch on Pixel 6a API 33 emulator.

## Implemented

- Single-module app (`:app`), package `com.samvaad.android`.
- `MainActivity : ComponentActivity` with `enableEdgeToEdge()` and
  `setContent { SamvaadTheme { Scaffold { Greeting("Samvaad") } } }`.
- Compose Material3 theme (`ui.theme.SamvaadTheme`, `Color.kt`, `Type.kt`)
  with dynamic color on Android 12+.
- `AndroidManifest.xml`: one exported `MainActivity` with `MAIN`/`LAUNCHER`,
  `Theme.Samvaad` window theme, `adjustResize`.
- Gradle: Kotlin DSL, version catalog (`gradle/libs.versions.toml`), AGP
  `9.4.1`, Kotlin `2.2.10`, Compose BOM `2026.02.01`.
- SDK: `minSdk 30`, `compileSdk 37`, `targetSdk 37`.
- Tests: default `ExampleUnitTest` (host) + `ExampleInstrumentedTest`
  (package-name check). No Samvaad tests yet.

## Planned (not started)

- Any Samvaad feature: login, enrollment, messaging, persistence, realtime.
- See `docs/roadmap.md`.

## Deferred / parked (explicitly out of scope for upcoming slices)

- TUI: parked.
- `samvaad-e2ee-lib` MessageStore implementation: parked.
- Web companion: future, no work in this repo.

## Unknown / undecided

- No Android architecture decided yet (no ViewModel/navigation/DI/database
  choice). Do not assume one.
- No networking stack, no local store, no E2EE adapter chosen.

## What this is not

- Not a thin-client copy of TUI architecture.
- Not an E2EE implementation.
- The unused `res/values/colors.xml` template entries and empty backup-rule
  placeholders are inherited template leftovers, not Samvaad design.
