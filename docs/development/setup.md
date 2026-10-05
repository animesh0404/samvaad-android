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

## LAN development TLS (debug builds only)

The LAN dev server serves HTTPS with a self-signed certificate (server
ADR 0017). The Android **debug** build trusts exactly that development
certificate for the LAN host, with normal hostname verification and no
cleartext. Release builds are unaffected: they keep Android's default
platform trust store.

- Server SAN requirement: the dev certificate must list
  `DNS:localhost`, `IP:127.0.0.1`, **and** `IP:<lan-ip>` (currently
  `IP:192.168.1.41`). Hostname verification fails otherwise.
- Debug trust anchor: `app/src/debug/res/raw/samvaad_dev_<ip>.pem`
  (public leaf certificate only).
- Debug config: `app/src/debug/res/xml/network_security_config.xml`,
  wired by `app/src/debug/AndroidManifest.xml`. Nothing under
  `src/debug` ships in release builds.

When the LAN IP changes:

1. Update `samvaad.tls.sans` in the server `application.yaml` (keep the
   existing entries, add `IP:<new-ip>`).
2. Delete ONLY the dev TLS keystore (SAN changes never auto-regenerate;
   never touch the release TLS volume) and restart the dev stack.
3. Confirm the new fingerprint in the server log
   (`[samvaad] Generated new TLS identity …`) matches
   `openssl s_client -connect <new-ip>:8080 | openssl x509 -fingerprint -sha256`,
   and that the SANs include the new IP.
4. Export ONLY the public leaf certificate and replace the debug
   `res/raw` PEM (same `samvaad_dev_<ip>` naming); update the debug
   Network Security Config domain if the IP changed.
5. Re-run `./gradlew :app:assembleDebug`,
   `./gradlew :app:testDebugUnitTest`,
   `./gradlew :app:assembleRelease`, and `git diff --check`.

Never commit private TLS material: keystores (`*.p12`), private keys,
keystore passwords, or `.env` secrets. Only the public PEM belongs in
`src/debug/res/raw`.

Physical-device troubleshooting: if the debug app reports "Cannot reach
the server" while the emulator on the same LAN succeeds, suspect an
on-device firewall (e.g. RethinkDNS) blocking LAN traffic for the app —
verify with `adb shell run-as com.samvaad.android nc -w5 <lan-ip> 8080`
versus plain `adb shell nc` (run-as works on debuggable builds).

## Conventions

- Kotlin DSL (`*.kts`), version catalog `gradle/libs.versions.toml`.
- One module (`:app`) until a slice explicitly requires another.
- Do not add dependencies without a slice requirement.
- Keep diffs small and the app launchable after every slice.
