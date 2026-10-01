# Samvaad Android

Android is the **PRIMARY** Samvaad device. Web will be a future COMPANION.

Current state: Android Studio-generated Jetpack Compose baseline that launches
and renders “Hello Samvaad!”. No Samvaad features exist yet.

## Repository layout

```text
samvaad-android/
├── app/            # Android application module (Compose UI, manifest, res)
├── docs/           # project documentation (map in docs/README.md)
├── gradle/         # version catalog + wrapper
├── README.md
├── AGENTS.md
├── settings.gradle.kts
├── build.gradle.kts
└── gradle.properties
```

## Baseline

- Package: `com.samvaad.android`
- Kotlin + Jetpack Compose + Kotlin DSL
- `minSdk = 30` (Android 11), `compileSdk = 37`, `targetSdk = 37`
- Verified launch on Pixel 6a API 33 emulator.
- Single `MainActivity` + `SamvaadTheme`, no navigation, no ViewModel, no DI.

## Boundaries (frozen for now)

Do not invent or change server APIs. The server is frozen at:

`464e07eb7acddf7f89e18be9425ca6f87a0875a7`

See `docs/api/server-checkpoint.md`. The exact integration sequence lives in
the server repo at `docs/api/android-integration-checklist.md` — it is not
duplicated here.

Explicitly **not implemented**: networking, authentication, device enrollment,
E2EE / Signal, database / message store, navigation, ViewModel, DI, background
work, push notifications, history sync.

## Build / test

```bash
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

`git diff --check` must be clean before committing.

See `docs/development/setup.md`, `docs/development/testing.md`,
`docs/architecture/current-state.md`, `docs/roadmap.md`, and `AGENTS.md`.
