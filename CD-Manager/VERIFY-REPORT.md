# CD Manager v0.5.1 — verification report

Date: 2026-09-12
Package ID: io.ciphertun.cdm

## Source checks completed

- Backend manifest: 10/10 backends present and uniquely identified.
- Removed obsolete `org.jetbrains.kotlin.android` plugin usage from all Android backend modules for AGP 9 built-in Kotlin.
- Searched project for obsolete `kotlinOptions`, `kotlin.sourceSets`, `applicationVariants`, `libraryVariants`, `variantFilter`, `BaseVariant`, `com.android.build.gradle`, and `buildDir` usages: none found in project source/configuration.
- XML resources parsed successfully with Python XML parser.
- Android launcher manifest now declares adaptive/round launcher icons.
- Launcher icon uses original CD Manager artwork: dark navy background, black archive/file-manager mark, black `CD Manager` text, adaptive foreground/background, and monochrome resource.
- Go backend unit tests: PASS (`go test ./...`).
- Python backend manifest/smoke verification script: PASS.
- Workflow toolchain updated to AGP 9.3.1 + Kotlin 2.4.20 + Gradle 9.7.0 + JDK 17 + compile/target SDK 37 + Build Tools 36.0.0 + NDK 29.0.14206865.
- Activity Compose updated to 1.13.0; Navigation Compose updated to 2.10.1; Preferences DataStore updated to stable 1.2.1.

## Important verification boundary

A full Android Gradle compilation could not be executed inside the packaging environment because the environment has no network/DNS access to download the Gradle distribution and Maven/Google dependencies, and the supplied source ZIP does not contain a Gradle wrapper or dependency cache.

Therefore this ZIP is source/configuration verified, not falsely labeled as a locally compiled APK. The included GitHub Actions workflow is the authoritative clean-room Android build path and installs the pinned SDK/NDK/toolchain versions before compiling the AARs and APK.
