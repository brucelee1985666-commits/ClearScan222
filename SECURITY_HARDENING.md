# Security hardening status

This document records the security changes in the `security-hardening` branch. It separates code changes from checks that still require a real Android build, device, or independently trusted release artifact.

## Implemented in source

### Document encryption
- New app-private image and PDF writes pass through `DocumentCrypto`.
- AES-256-GCM (`AES/GCM/NoPadding`) uses a 96-bit random IV and 128-bit authentication tag.
- The AES key is generated and retained by Android Keystore; it is not stored in preferences or exported.
- The encrypted file format is `CSG2 || IV || ciphertext || GCM tag`, with the magic header authenticated as GCM additional data.
- Decryption writes to a temporary file and publishes it only after GCM authentication succeeds.
- Existing plaintext files referenced by the document and draft databases are migrated in a one-time startup pass before the library is shown; any missed app-private file is lazily migrated on first successful read or explicit export/share.
- Explicit sharing/export creates a temporary plaintext cache copy. The app removes staging files on the next startup; users should treat the chosen share/export destination as an intentional disclosure.

### Legacy password field
- The old password lock stored raw password strings and did not encrypt or gate document access.
- The password-only feature is disabled rather than represented as document encryption.
- Legacy `passwords` entries are removed from the old SharedPreferences file and the DataStore key is removed on load/save.
- Existing user-defined password strings are not migrated; they were not cryptographic keys and must not be relied upon.

### Backups and transport
- `android:allowBackup=false`.
- Explicit exclusions cover app-private files, databases, preferences, and app-specific external files for legacy backup and Android 12+ data extraction/device transfer rules.
- Android network security configuration rejects cleartext traffic.

### Build and supply chain
- Maven repositories are restricted to Google Maven, Maven Central, and the Gradle Plugin Portal; the unverified Aliyun mirrors were removed.
- The root ignore rule for `models/` was scoped to `/models/`; it had unintentionally excluded `third_party/llama.cpp/src/models/` from the repository.
- The vendored llama.cpp tree is still incomplete: `src/llama-model.cpp` includes `models/models.h`, but `third_party/llama.cpp/src/models/` and its model implementation files are absent. The security CI therefore uses the explicit `-PskipLlamaNativeBuild=true` switch to compile Kotlin/Java, run JVM tests/lint, assemble a debug APK, and verify its signature without the native inference library. This CI APK is not a full functional release build.
- Release CI deliberately does not skip native compilation; a release remains blocked until the missing model sources are restored from a matching, pinned llama.cpp revision.
- Gradle 9.4.1 is fetched from `services.gradle.org` with the official SHA-256:
  `2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb`.
- The Gradle 9.4.1 Wrapper JAR was compared with the official Gradle 9.4.1 artifact; SHA-256:
  `55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c`.
- GitHub Actions are pinned to immutable commit SHAs.
- Direct dependency versions are pinned in the version catalog.
- The first CI run bootstraps Gradle dependency verification metadata and uploads it as a short-lived artifact for review. That metadata must be reviewed and committed as `gradle/verification-metadata.xml`; release builds intentionally fail until it exists.

## Network review

A source review of the app's network entry points found:
- GitHub release metadata and APK downloads in the updater.
- User-selected translation model downloads.
- No app code path that posts captured images or document files to a ClearScan server.
- File sharing/export is initiated by explicit user actions through Android intents or MediaStore.

This is a source-level review, not a packet-capture result. Runtime traffic capture on an Android device/emulator has not yet been performed, so the no-unexpected-egress requirement remains open until a device test records destinations and confirms that no scan bytes are transmitted during capture, browsing, or idle operation.

## APK signature verification

- CI runs `apksigner verify --verbose --print-certs` on the built APK and records its SHA-256.
- Release CI also compares the signer certificate against the repository variable `CLEARSCAN_SIGNING_CERT_SHA256`.
- That variable must be populated with a fingerprint obtained independently from a trusted release APK/certificate. It has not been inferred from the source tree.
- The existing updater compares the downloaded APK signer with the installed app signer, but that alone is not independent trust establishment.

## Required verification before calling this secure/release-ready

1. Run the Android unit tests, lint, and debug APK assembly in GitHub Actions.
2. Review and commit the generated `gradle/verification-metadata.xml`, then rerun CI so dependencies are verified against the committed baseline.
3. Run `DocumentCryptoTest` on an Android emulator or physical device; verify both round-trip and modified-ciphertext rejection.
4. Run packet capture during idle, capture, document open, model download, update check, and explicit share/export. Confirm scan/document payloads appear only in the explicit share/export case.
5. Independently obtain the official release signer fingerprint, set `CLEARSCAN_SIGNING_CERT_SHA256`, and verify the release APK signature and checksum.
6. Test migration with a copy of a pre-hardening app data directory and confirm existing documents remain readable after encryption.

Until these checks are complete, this branch is a security-hardening candidate, not a certified or release-ready build.
