# CD Manager — Universal File Intelligence

Application ID: `io.ciphertun.cdm`

CD Manager is a local-first Android file intelligence and configuration toolkit.
It is designed to analyze ordinary files as well as VPN/tunneling configuration
formats without pretending that an unsupported proprietary format can be decrypted.

## Intelligent application and protocol detection

CD Manager does not treat an extension as an arbitrary app label. It combines the extension with content signatures and format fingerprints. For example, `.stk` is identified as **Stark VPN**, `.dark` as **Dark Tunnel**, `.hat` as **HA Tunnel Plus**, `.ehi` as **HTTP Injector**, `.hc` as **HTTP Custom**, `.ziv` as **ZIVPN**, and `.ktr` as **KPN Tunnel Revolution** when evidence supports those identities. Unknown or conflicting files are reported as unknown rather than being mislabelled.

Protocol detection is separate from app detection. The analysis layer is designed for SSH, HTTP/HTTPS, SOCKS, OpenVPN, WireGuard, TCP, UDP, ICMP, TLS, WebSocket, gRPC, QUIC/HTTP/3, VLESS, VMess, Trojan, Shadowsocks, Reality, Hysteria/Hysteria2, TUIC, NaiveProxy, MTProto and DNS tunneling. V2Ray/Xray is therefore only one protocol family among many.

See `PROTOCOL-COVERAGE.md` for the current protocol model and `docs/FEATURE-RESEARCH.md` for research and sources.

## Architecture

The Android frontend is Kotlin + Jetpack Compose. CPU-heavy local analysis uses a
pure-Go engine packaged with gomobile. Android-specific operations stay in Kotlin:
Storage Access Framework, streaming I/O, Keystore/biometrics, permissions and UI.

The engine router chooses a capable backend instead of launching every backend.
Independent analysis jobs run concurrently so hashing, format detection, metrics and
UI preparation do not block each other. The project has exactly 10 required backend families. Node.js and Python are required CI/desktop parity backends; Android uses the eight Android-compatible engines and never attempts to launch a missing desktop runtime; Node.js and Python are validated as parity engines in CI and remain outside the APK because shipping full desktop runtimes would add startup and size overhead.

## Universal ABI

The GitHub workflow builds the Go AAR for Android's four supported non-deprecated
application ABIs: `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`. The final release
APK therefore carries native Go libraries for all four architectures.

## Configuration formats

Recognized format families include Dark Tunnel, HTTP Injector, HTTP Injector Lite,
HA Tunnel Plus, HTTP Custom, ZIVPN, KPN Tunnel Revolution and many public tunnel
configuration extensions. Detection is separate from decryption: a protected or
unknown variant is reported honestly.

Dark Tunnel has a real local decryptor. Human-readable results are presented as
labelled details such as Config Type, Name, Server, Port, SNI, TLS, Proxy, HTTP
Payload, DNS, SSH and V2Ray/Trojan information. A Raw Format action exposes the
structured representation when requested.

## Generic file capabilities

- streaming SHA-256/SHA-1/MD5 hashing
- entropy and printable-text analysis
- magic-byte/file-type detection
- strings and hex preview
- archive-format recognition
- AES-256-GCM CDM encrypted files
- SAF open/save support
- complete recovered configuration fields, credentials, and configuration messages when a parser can recover them
- adapter registry for additional formats
- settings and diagnostics

## Fast GitHub build

The workflow uses Gradle configuration/build caching, parallel task execution and a
cacheable Go AAR. On unchanged Go backend sources the expensive gomobile bind step
is restored from GitHub Actions cache. Subsequent Gradle builds reuse configuration
and task outputs where possible.

The first CI build is necessarily slower because Android SDK components, Gradle
artifacts and the Go mobile toolchain must be provisioned. Later builds are designed
to be substantially faster.

## Important

No signing keys, passwords, API keys or private configuration secrets belong in the
repository. Release signing can be added with GitHub Secrets without placing a
keystore in this ZIP.
