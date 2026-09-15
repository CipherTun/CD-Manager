plugins { id("com.android.library") }

android { namespace = "io.ciphertun.cdm.backend.format"; compileSdk = 37; defaultConfig { minSdk = 26 } }
kotlin { jvmToolchain(17) }
