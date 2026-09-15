# Universal decoding and format coverage

CD Manager v0.6.0 applies a format-agnostic decoding layer to every imported file, regardless of extension. Reversible layers that can be validated locally are attempted in parallel: Base64, Base64URL, hexadecimal, GZIP and ZLIB. The original file is never modified.

Specialized adapters remain separate from generic decoding. A VPN/tunnel extension is not treated as proof that a proprietary encrypted container can be decrypted. A successful decryption is reported only when a verified adapter produces structurally valid output.

The registry includes the existing VPN/tunnel inventory plus additional common configuration/container extensions. Formats whose public implementation details are unavailable or version-dependent are still detected and analyzed generically; they are not falsely labelled as decrypted.

## Implemented verified decryption

- Dark Tunnel: outer Base64/JSON, AES-CFB layers and MessagePack normalization used by the supported public container variant.
- CDM2: AES-256-GCM file encryption/decryption with password-derived keys.

## Generic capabilities for every file

- extension and content/magic identification
- MIME inference
- SHA-256, SHA-1 and MD5
- entropy and printable ratio
- strings extraction
- hex preview
- protocol fingerprints
- reversible decoding candidates in parallel
- archive/container detection

More proprietary VPN adapters should be added only with reproducible algorithms and test vectors.
