# Development Setup

## Toolchain

- JDK 25 (host reports `openjdk 25.0.4.1`; Gradle daemon toolchain resolves
  via foojay, see `gradle/gradle-daemon-jvm.properties`).
- Android SDK via `local.properties` `sdk.dir` (machine-local, never commit).
- Checked-in Gradle wrapper (`./gradlew`), Gradle `9.6.0`.
- Android Studio generated the project; CLI builds use the wrapper.

## Run

- Emulator verified: Pixel 6a, API 33 (Android 13).
- `minSdk 30` (Android 11); `compileSdk/targetSdk 37` as generated.
- Launch via Android Studio Run, or build APK:

```bash
./gradlew :app:assembleDebug
```

## Conventions

- Kotlin DSL (`*.kts`), version catalog `gradle/libs.versions.toml`.
- One module (`:app`) until a slice explicitly requires another.
- Do not add dependencies without a slice requirement.
- Keep diffs small and the app launchable after every slice.
