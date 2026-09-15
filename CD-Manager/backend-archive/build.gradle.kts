plugins { id("com.android.library") }

android { namespace = "io.ciphertun.cdm.backend.archive"; compileSdk = 37; defaultConfig { minSdk = 26 } }
kotlin { jvmToolchain(17) }

dependencies { implementation("org.apache.commons:commons-compress:1.28.0") }
