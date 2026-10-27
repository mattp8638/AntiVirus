import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing: put keystore.properties (storeFile, storePassword, keyAlias, keyPassword) next to this
// project, or set FENRIR_ANDROID_KEYSTORE* in CI. The keystore itself is never committed.
val signing = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
    System.getenv("FENRIR_ANDROID_KEYSTORE")?.let { put("storeFile", it) }
    System.getenv("FENRIR_ANDROID_KEYSTORE_PASSWORD")?.let { put("storePassword", it); put("keyPassword", it) }
    System.getenv("FENRIR_ANDROID_KEY_ALIAS")?.let { put("keyAlias", it) }
}

android {
    namespace = "uk.co.fenrirsecurity.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "uk.co.fenrirsecurity.agent"
        minSdk = 26
        targetSdk = 35
        versionCode = (System.getenv("FENRIR_ANDROID_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("FENRIR_ANDROID_VERSION_NAME") ?: "0.1.0"
    }

    signingConfigs {
        if (signing.getProperty("storeFile") != null) {
            create("release") {
                storeFile = file(signing.getProperty("storeFile"))
                storePassword = signing.getProperty("storePassword")
                keyAlias = signing.getProperty("keyAlias")
                keyPassword = signing.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
    // The first CI builds report lint findings (uploaded with the APK) without failing; make it strict once clean.
    lint { abortOnError = false; checkReleaseBuilds = false }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    // QR scanning through Google Play services: no camera permission, the scanner UI is Google's.
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
