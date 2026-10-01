# ADR 0004: Android Keystore-Backed Local Crypto Vault

- Status: Accepted (implemented; local-only, not a product/distribution decision)
- Date: 2026-10-01

## Context

The spike (ADR 0003) kept libsignal private material in memory only, so
process death, app restart, or reboot destroyed the device identity. The
next slice needed durability without enrollment, UI, passwords, or server
changes.

## Decision

Envelope architecture, nothing else:

- libsignal canonical record blobs (`IdentityKeyPair`, `SignedPreKeyRecord`,
  `KyberPreKeyRecord`, `PreKeyRecord` serialization, libsignal 0.86.5)
  → AES-256-GCM encrypt → versioned envelope files under
  `getNoBackupFilesDir()/crypto-vault` (device-bound: excluded from cloud
  backup and device-to-device transfer by location, no backup XML needed).
- Android Keystore holds exactly one non-exportable wrapping key
  (`samvaad-crypto-vault-v1`, encrypt/decrypt, GCM/NoPadding, no
  biometric/lockscreen requirement, no StrongBox mandate). It never holds
  libsignal material; key bytes are never read or written.
- AAD binds schema version + record kind + handle UUID to each ciphertext;
  fresh random IV per encryption, stored in the envelope.
- Handles gained a stable kind tag (`IDENTITY`, `SIGNED_PREKEY`,
  `KYBER_PREKEY`, `ONE_TIME_PREKEY`); UUID stays the vault/store key.
  The adapter owns libsignal math and typed export/import; the vault owns
  encryption, files, and version/integrity checks. No passwords, no
  BouncyCastle, no custom crypto (platform Keystore + `javax.crypto` only).

## Fail-closed contract (verified by tests)

Missing wrapping key, GCM failure, truncation, unknown version, kind/UUID
mismatch, libsignal reconstruction failure, and missing records all throw
typed errors. Nothing in these paths creates keys, regenerates identity,
or falls back to plaintext. In particular, encrypted-data-without-key
(the restore/clone case) refuses rather than re-enrolling silently.

## Evidence

- 13 unit tests (envelope, AAD, corruption, isolation, no-plaintext,
  reopen-recovery) + spike tests: 32/32 host-JVM pass.
- Instrumented on Pixel 6a API 33 x86_64 emulator and physical Pixel 6a
  (arm64-v8a): Keystore round-trip of identity/signed/Kyber/5 OTPKs with
  libsignal re-verification; corruption and missing-alias fail-closed
  (no replacement key minted); no plaintext in stored files.
- Real lifecycle on both devices: force-stop → relaunch → recover PASS;
  physical-device reboot → recover PASS.

## Consequences

### Still outstanding (not decided here)

- AGPL-3.0-only distribution decision for any shipped artifact.
- Enrollment, server device IDs/roles/state, recovery UX, sessions,
  messaging, OTPK provisioning policy, Room/persistence beyond the vault.
- Wrapping-key rotation, hardware-backing policy, backup-rule XML
  belt-and-braces (no-backup dir is the current protection).

### Negative

- Native record formats are libsignal-internal: the 0.86.5 pin and the
  envelope schema version must move together; unknown versions refuse.
- In-memory plaintext hygiene is best-effort (zeroed where practical).
