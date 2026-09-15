# CD Manager backend system

CD Manager has exactly 10 required backend families. Android-compatible engines are packaged as AARs and included in the APK build; Node.js and Python are required CI/desktop parity engines.

The app uses `EngineRouter` as the single capability router. Application/format/protocol intelligence determines the jobs needed for a file, and the router selects only compatible engines. Independent jobs can execute in parallel. A backend is never launched solely because it is installed.

Required families:
1. Kotlin Core
2. Go Native
3. Java/JCA
4. Apache Commons Compress
5. MessagePack
6. Android Platform/SAF
7. Format Intelligence
8. Protocol Intelligence
9. Node.js parity
10. Python parity

The Node.js and Python runtimes cannot be represented honestly as Android AARs, so CI validates and packages them instead of pretending they are mobile libraries.
