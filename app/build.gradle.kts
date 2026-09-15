plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.ciphertun.cdm"
    compileSdk = 37
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.ciphertun.cdm"
        minSdk = 26
        targetSdk = 37
        versionCode = 6
        versionName = "0.6.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug { applicationIdSuffix = ".debug" }
    }

    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

kotlin { jvmToolchain(17) }

// Compose BOM is declared directly inside dependencies
dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
    implementation(platform("androidx.compose:compose-bom:2026.08.00"))
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.08.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3:1.4.0")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.navigation:navigation-compose:2.10.1")
    implementation("androidx.documentfile:documentfile:1.1.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.datastore:datastore-preferences:1.2.1")
    implementation("org.apache.commons:commons-compress:1.28.0")
    implementation("org.msgpack:msgpack-core:0.9.10")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
