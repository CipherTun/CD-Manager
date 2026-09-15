# CD Manager — 10 required backend families

The project contains ten required backend families. The Android runtime uses the capability-compatible Android engines; Node.js and Python are required CI/desktop parity engines and are never launched on Android where no runtime exists.

| # | Backend | Runtime | Primary jobs | Android AAR |
|---|---|---|---|---|
| 1 | Kotlin Core | Android | file orchestration, crypto coordination | yes |
| 2 | Go Native | Android | fast hashing, entropy, binary metrics | yes |
| 3 | Java/JCA | Android | cryptography/hash primitives | yes |
| 4 | Apache Commons Compress | Android | archive/container analysis | yes |
| 5 | MessagePack | Android | MessagePack structures | yes |
| 6 | Android Platform / SAF | Android | URI/file access | yes |
| 7 | Format Intelligence | Android | application/format identity | yes |
| 8 | Protocol Intelligence | Android | protocol/transport identity | yes |
| 9 | Node.js | CI/desktop | cross-engine parity/adapter | no (required CI tool) |
| 10 | Python | CI/desktop | cross-engine parity/adapter | no (required CI tool) |

The intelligent router selects the smallest compatible set for each job. It does not start an unsuitable backend merely because it exists. Independent engines can be used in parallel.
