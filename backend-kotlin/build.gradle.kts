plugins { id("com.android.library") }

android { namespace = "io.ciphertun.cdm.backend.kotlin"; compileSdk = 37; defaultConfig { minSdk = 26 } }
kotlin { jvmToolchain(17) }
