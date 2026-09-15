plugins { id("com.android.library") }

android { namespace = "io.ciphertun.cdm.backend.android"; compileSdk = 37; defaultConfig { minSdk = 26 } }
kotlin { jvmToolchain(17) }
