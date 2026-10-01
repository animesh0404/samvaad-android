plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.samvaad.android"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.samvaad.android"
        minSdk = 30
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        // Required by org.signal:libsignal-android:0.86.5 (uses Java 8+
        // core-library APIs). Local spike only.
        isCoreLibraryDesugaringEnabled = true
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources {
            // libsignal-client (JVM jar, pulled transitively by the Android
            // AAR) bundles desktop natives that must not ship in the APK.
            // Per signalapp/libsignal README "Use as a library".
            excludes += setOf("libsignal_jni*.dylib", "signal_jni*.dll")
        }
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
}

// Slice 1: Robolectric host UI tests run on JDK 21. Robolectric 4.17 cannot
// run on JDK 25 (FileDescriptor shadow hits strong encapsulation).
tasks.withType<Test>().configureEach {
    javaLauncher.set(
        javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    )
    // Required by Robolectric's FileDescriptor shadow on Java 21+
    // (ApplicationSharedMemory setup at SDK 36+).
    jvmArgs("--add-opens=java.base/jdk.internal.access=ALL-UNNAMED")
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // LOCAL-ONLY feasibility spike: exact aligned pair with server/e2ee-lib
    // (org.signal:libsignal-client:0.86.5). The Android AAR carries the
    // Android JNI natives; the client JAR carries the shared Java API.
    // AGPL-3.0-only: local spike only, NOT a distribution artifact.
    implementation(libs.libsignal.android)
    implementation(libs.libsignal.client)
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    testImplementation(libs.junit)
    testImplementation(libs.androidx.compose.ui.test.junit4)
    testImplementation(libs.robolectric)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}