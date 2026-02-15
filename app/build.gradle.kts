plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("com.google.devtools.ksp")
    kotlin("kapt")
}


android {
    namespace = "com.cybersentinel.app"
    compileSdk = 35


    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.cybersentinel.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        vectorDrawables { useSupportLibrary = true }

        // NDK: LLM inference is arm64-only (32-bit falls back to template engine)
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    // CMake build configuration for libllama_jni.so
    // Enabled only when llama.cpp source tree is present (LLAMA_CPP_BUILD=true)
    if (project.findProperty("LLAMA_CPP_BUILD") == "true") {
        defaultConfig {
            externalNativeBuild {
                cmake {
                    arguments(
                        "-DLLAMA_CPP_DIR=${projectDir}/src/main/cpp/llama.cpp",
                        "-DANDROID_STL=c++_shared"
                    )
                    cppFlags("-std=c++17", "-O3", "-ffunction-sections", "-fdata-sections")
                }
            }
        }
        externalNativeBuild {
            cmake {
                path = file("src/main/cpp/CMakeLists.txt")
                version = "3.22.1"
            }
        }
    }


    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug { isMinifyEnabled = false }
    }


    buildFeatures {
        compose = true
        buildConfig = true
    }


    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

ksp { arg("room.schemaLocation", "$projectDir/schemas") } // silences Room warning

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
// Kotlin + Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.google.android.material:material:1.12.0")


// Compose BOM
    implementation(platform("androidx.compose:compose-bom:2025.01.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.navigation:navigation-compose:2.8.0")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")


// Splash
    implementation("androidx.core:core-splashscreen:1.0.1")


// Hilt
    implementation("com.google.dagger:hilt-android:2.52")
    kapt("com.google.dagger:hilt-compiler:2.52")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")


// DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.datastore:datastore-core:1.1.1")


// Retrofit + Moshi + OkHttp
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.retrofit2:converter-scalars:2.11.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    ksp("com.squareup.moshi:moshi-kotlin-codegen:1.15.1")
    implementation("com.squareup.okhttp3:logging-interceptor:5.0.0-alpha.14")


// Room (KSP)
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")


// DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.1")


// WorkManager + Hilt integration
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("androidx.hilt:hilt-work:1.2.0")
    ksp("androidx.hilt:hilt-compiler:1.2.0")

// Notifications compat
    implementation("androidx.core:core-ktx:1.13.1")


// CameraX (QR scanner module base)
    implementation("androidx.camera:camera-core:1.3.4")
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    
// ML Kit for QR/Barcode scanning
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    
// Permissions for camera
    implementation("com.google.accompanist:accompanist-permissions:0.32.0")

// Testing
    testImplementation("junit:junit:4.13.2")
}

kapt {
    correctErrorTypes = true
}