# ADR 0002: Android Build Baseline

- Status: Accepted
- Date: 2026-10-01

## Context

Android Studio generated a working Kotlin + Compose project that launches on
the Pixel 6a API 33 emulator. The bootstrap must preserve that baseline
without premature architecture.

## Decision

Keep the generated baseline unchanged except the already-tested
“Hello Samvaad!” text:

- Package `com.samvaad.android`, single `:app` module.
- Kotlin DSL + version catalog; AGP `9.4.1`, Kotlin `2.2.10`,
  Compose BOM `2026.02.01`.
- `minSdk 30`, `compileSdk 37`, `targetSdk 37`.
- Single `MainActivity` Compose UI, no navigation/ViewModel/DI/database.
- No new dependencies at bootstrap.

## Consequences

### Positive

- Buildable, runnable starting point the developer understands.
- Small reviewable diffs for upcoming learning slices.

### Negative

- Template leftovers remain (`colors.xml` unused entries, empty backup
  placeholders, `GreetingPreview("Android")` param). Intentional: cleanup
  belongs to the UI-hygiene slice, not bootstrap.

## Scope

Bootstrap only. Architecture choices (networking, storage, E2EE adapter,
navigation, ViewModel, DI) require their own ADRs when their slices arrive.
