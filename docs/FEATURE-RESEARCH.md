# CD Manager feature research

## Executive direction

CD Manager should combine three capabilities that are usually separate: a serious Android file manager, a forensic-style file analyzer, and a format-aware configuration/crypto engine. The strongest architecture is local-first, SAF-native, streaming, adapter-based and honest about what is actually parsed or decrypted.

## 1. File intelligence

Recommended core features:

- extension and magic-byte identification
- MIME inference
- file size, timestamps and provider metadata
- SHA-256/SHA-1/MD5 plus optional SHA-512
- entropy and printable-text analysis
- strings extraction
- paginated hex viewer/editor
- duplicate and large-file finder
- empty-folder and leftover analysis
- file tagging/favorites and operation history
- archive tree inspection before extraction
- safe extraction with path-traversal protection
- document/image/audio/video metadata where Android APIs can provide it

The open-source FileExplorer project demonstrates a useful breadth: checksum verification, integrity watches, tags, APK analysis, PDF/document previews and a paginated hex editor. AF-File-Manager similarly demonstrates large-file/duplicate analysis and multiple remote storage protocols. citeturn1search6turn1search14

## 2. VPN/tunnel configuration intelligence

Maintain an adapter registry instead of one giant parser. Every adapter has:

- extension candidates
- magic/content signatures
- app/format name
- version detection
- parse capability
- decrypt capability
- encrypt capability
- test vectors
- security notes
- complete recovered credential/configuration display policy

Initial registry should include `.dark`, `.ehi`, `.ehil`, `.hat`, `.hc`, `.ziv`, `.ktr`, `.maya`, `.jz`, plus the broader community inventory already registered in the app. Detection can be broad; decryption must be narrow and evidence-based.

### Dark Tunnel

The researched Dark Tunnel format is a base64-encoded outer JSON shell containing `encryptedLockedConfig`. The encrypted payload is AES-CFB-256 decrypted, decoded as MessagePack, then the nested `EncryptedLockedConfig` is AES-CFB-192 decrypted and recursively cleaned. The public implementation explicitly describes this sequence. citeturn1search2turn1search8

CD Manager therefore presents the result as labelled fields rather than dumping JSON by default. The raw structured result remains one explicit button away.

### HTTP Custom

`.hc` should be implemented as a versioned adapter. The maintained public HCTools decryptor documents multiple keys because the application changed keys across versions; therefore a robust adapter should identify version/key candidates and verify decrypted structure rather than blindly trying one hard-coded key. citeturn1search0

### Other formats

`.hat`, `.ehi`, `.ktr`, `.ziv`, `.maya` and `.jz` should stay in detected/analysis mode until a reproducible parser/decryption algorithm and test corpus are established. This prevents a dangerous false-positive "decrypted" label.

## 3. Archives and compression

Apache Commons Compress is a strong local engine for common archive/compression formats. Its current documentation lists ZIP, 7z, tar, ar, cpio, arj and multiple compressor formats including gzip, bzip2, XZ, LZMA, Brotli and Zstandard. citeturn0search2turn0search13

Recommended UI:

- archive browser
- preview entry metadata
- extract selected/all
- create ZIP/TAR/TAR.GZ
- password-protected ZIP handling where supported by the selected engine
- archive bomb / huge-expansion warnings
- path traversal protection
- nested archive depth limit

## 4. Encryption and secure vault

Use Android Keystore for long-lived keys and hardware-backed protection where available. Android's security guidance recommends secure random generation and Keystore for persistent cryptographic keys. citeturn0search1turn0search11turn0search12

Recommended CD Manager crypto layers:

1. CDM2 password-encrypted files: AES-256-GCM + random salt/IV + PBKDF2-HMAC-SHA256.
2. Android Keystore-backed vault master key.
3. Biometric/device-credential gate for key reveal and sensitive exports.
4. Modern age-compatible encryption as a separate adapter, preferably using a maintained streaming engine.
5. Secure cleanup of partial outputs after failed authentication/decryption.

The Age Android project is particularly useful as an architecture reference because it combines SAF, streaming I/O, batch processing, Go encryption, Keystore-protected private keys, biometric gating and detailed history. citeturn1search1

AgePonyAndroid is another useful reference for streaming age operations, SSH identities, armor, hybrid keys and biometric key-vault design. citeturn1search3

## 5. Security and malware analysis

Add an optional offline scanner layer rather than making network scanning mandatory. Hypatia demonstrates a local ClamAV-style signature approach with low battery impact and optional real-time scanning. citeturn1search5turn1search11

For Android-focused files, HydraDragonAV-Mobile demonstrates a native scanner architecture combining YARA-X/ClamAV-style matching with archive traversal and Android artifact analysis. citeturn1search13

Recommended CD Manager result model:

- clean / no signature hit
- suspicious heuristic
- signature match
- scan unavailable
- scan skipped because type is unsupported

Never present a heuristic as proof of malware.

## 6. APK and Android package analysis

A dedicated APK analyzer is a high-value addition:

- package name and version
- min/target SDK
- permissions
- exported components
- services/receivers/providers
- signing certificate fingerprints
- DEX count and sizes
- native library ABI inventory
- ZIP directory and compression statistics
- suspicious permission combinations
- embedded URLs/domains/strings

The FileExplorer research implementation already demonstrates manifest, permissions, signing certificate SHA-256, shared UID, DEX method count and ZIP size analysis. citeturn1search6

## 7. Universal Android architecture

Android's current ABI documentation identifies `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` as the main supported ABIs. Google separately documents the 32-bit/64-bit ARM mapping and Play's 64-bit requirements. citeturn0search0turn0search10

The current CD Manager core deliberately uses Kotlin/Java for its implemented engines, so it does not ship architecture-specific native libraries. That means the same APK can run on ARMv7, ARM64, x86 and x86_64 devices. If a future Go/Rust/native engine is added, the CI must build all four ABIs and verify the APK contents before release.

## 8. Storage and file access

The app should use Android's Storage Access Framework and persist URI permissions instead of assuming raw filesystem paths. This allows files from Downloads, SD cards, document providers and cloud-backed providers to participate in the same workflow.

## 9. Remote storage

A future file-browser module can add FTP, SFTP, SMB and WebDAV. Material Files demonstrates these protocols in an Android file manager, while Voyager provides a current Material 3 example with local storage plus SFTP/FTP/SMB/WebDAV and background transfer handling. citeturn0search7turn0search18

Remote protocols should be opt-in, credentials stored through Keystore-backed secrets, and all remote actions visibly labelled. Local analysis should remain fully usable without accounts.

## 10. UX architecture

Recommended bottom navigation:

- **Files** — browse/open/share/manage files
- **Analyze** — deep inspection, hashes, strings, hex, metadata
- **Crypto** — encrypt/decrypt/vault/key management
- **Settings** — security, appearance, adapter diagnostics, updates, licenses

A selected file should open a single "intelligence" screen with sections:

**Identity → Detection → Parsed details → Security → Hashes → Strings → Hex → Raw → Actions**

For VPN configs, the parsed-details section should read naturally:

- Config type: TROJAN
- Name: …
- Server: …
- Port: …
- SNI/serverName: …
- Transport: TCP + TLS
- Proxy: …
- HTTP payload: …
- DNS: …
- SSH: …
- V2Ray/Trojan: …

The raw JSON/MessagePack-normalized representation belongs behind **Raw Format**, not in the default result.

## 11. Reliability requirements

Every format adapter should have:

- positive test vectors
- negative test vectors
- corrupted-file tests
- wrong-password tests where applicable
- version/key tests
- bounded memory tests
- large-file tests
- output cleanup tests
- regression tests for every previously fixed bug

The CI workflow should build debug and release, run unit tests, verify the final APK exists, inspect native-library ABI contents, and upload the APK artifacts. Release signing should use GitHub Secrets only.

## 12. Recommended implementation order

**Phase A:** Dark Tunnel production adapter + current analysis UI + raw view + streaming CDM2 + tests.

**Phase B:** archive browser/extractor, APK analyzer, certificate/PEM parser, richer metadata, duplicate/large-file tools.

**Phase C:** versioned HTTP Custom `.hc` adapter, then evidence-backed `.ehi`, `.hat`, `.ziv`, `.ktr` parsers.

**Phase D:** age-compatible encryption, Keystore vault, biometrics, key management and batch operations.

**Phase E:** optional offline malware/YARA layer and remote file protocols.

**Phase F:** native engines only where they provide a real capability that cannot be implemented reliably in Kotlin/Java; when introduced, package all four Android ABIs and keep a universal fallback strategy.

## 2026-09-12 update — semantic application identification and protocol-neutral parsing

CD Manager must not equate an extension with an unrelated application. The detection engine now treats the extension as one signal and can override it with trusted content signatures. For example, `.stk` is associated with **Stark VPN**, while `.dark` is associated with **Dark Tunnel**. HA Tunnel Plus documents `.hat` as its encrypted configuration export, ZIVPN documents `.ziv`, and public decryption research documents `.ehi` as HTTP Injector and Dark Tunnel as a separate format. See: https://play.google.com/store/apps/details?id=com.hatunnel.plus, https://zivpn.com/config_for_zivpn.html, https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS.

The protocol layer is deliberately independent of the application layer. A configuration can contain one or multiple transport/protocol technologies, so the app should never be hard-coded around V2Ray/Xray. The protocol detector therefore recognizes, where evidence is present, SSH, HTTP/HTTPS, SOCKS, OpenVPN, WireGuard, TCP, UDP, ICMP, TLS, WebSocket, gRPC, QUIC/HTTP3, VLESS, VMess, Trojan, Shadowsocks, Reality, Hysteria/Hysteria2, TUIC, NaiveProxy, MTProto and DNS tunneling. This is analysis metadata; CD Manager does not claim that every detected protocol is decryptable or executable.

The architecture follows a capability model:

1. **Identify application** — extension + magic/signature + content fingerprint.
2. **Identify format/version** — only after application confidence is established.
3. **Select adapter** — choose the smallest engine that can actually handle that format.
4. **Parse/decrypt** — run only supported operations; protected/unknown variants remain explicitly unsupported.
5. **Normalize** — map results into common fields such as server, port, SNI, transport, proxy, payload, DNS, credentials, TLS, authentication and routing.
6. **Present** — show human-readable fields first; offer Raw Format separately.

This separation is also important for performance: generic file analysis, hashing and UI work remain independent from specialized format engines. Optional engines are selected by the router rather than launched indiscriminately.

### Useful non-VPN capabilities worth retaining

Research into current open-source Android file managers and APK analyzers supports adding archive browsing/extraction, secure file operations, checksum verification, APK manifest/signing/DEX analysis, hex/string inspection, encrypted vaults, biometric gating, saved searches, tags, and bounded background jobs. AF File Manager and SysAdminDoc/FileExplorer demonstrate several of these capabilities in modern Compose applications. APK Auditor and Martin Styk's APK Analyzer demonstrate detailed APK/security inspection concepts.

Sources:
- HA Tunnel Plus: https://play.google.com/store/apps/details?id=com.hatunnel.plus
- ZIVPN configuration documentation: https://zivpn.com/config_for_zivpn.html
- Public configuration decryption research: https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS
- AF File Manager: https://github.com/sinegard/AF-File-Manager
- FileExplorer: https://github.com/SysAdminDoc/FileExplorer
- APK Auditor: https://github.com/thecybersandeep/apkauditor
- Android APK Analyzer: https://github.com/MartinStyk/apk-analyzer
- Go Mobile: https://go.dev/wiki/Mobile
