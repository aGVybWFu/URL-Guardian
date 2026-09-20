plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Production signing is driven exclusively by environment variables so no secret
// ever lands in the repository, gradle.properties, local.properties or shell
// history. Values are never logged or printed; only SET / NOT SET is reported.
// The keystore itself must live outside the repository.
val productionKeystorePath = providers.environmentVariable("URL_GUARDIAN_KEYSTORE_PATH").orNull
val productionKeyAlias = providers.environmentVariable("URL_GUARDIAN_KEY_ALIAS").orNull
val productionKeystorePassword = providers.environmentVariable("URL_GUARDIAN_KEYSTORE_PASSWORD").orNull
val productionKeyPassword = providers.environmentVariable("URL_GUARDIAN_KEY_PASSWORD").orNull
val productionKeystoreType = providers.environmentVariable("URL_GUARDIAN_KEYSTORE_TYPE").orNull ?: "PKCS12"
val productionSigningConfigured = listOf(
    productionKeystorePath, productionKeyAlias, productionKeystorePassword, productionKeyPassword,
).all { !it.isNullOrBlank() }
val productionKeystoreFile = productionKeystorePath?.takeIf { it.isNotBlank() }?.let { rootProject.file(it) }
val productionKeystoreInsideRepo = productionKeystoreFile?.let { candidate ->
    runCatching { candidate.canonicalPath.startsWith(rootProject.projectDir.canonicalPath) }.getOrDefault(false)
} ?: false

if (productionSigningConfigured && productionKeystoreFile?.exists() != true) {
    throw GradleException(
        "Production signing is configured but the keystore file was not found. " +
            "Check URL_GUARDIAN_KEYSTORE_PATH (its value is never printed).",
    )
}
if (productionSigningConfigured && productionKeystoreInsideRepo) {
    throw GradleException("The production keystore must not live inside the repository.")
}
logger.lifecycle(
    "Production signing: " + if (productionSigningConfigured) "SET" else "NOT SET (release artifacts stay unsigned)",
)

android {
    namespace = "org.urlguardian.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.urlguardian.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 11
        versionName = "1.0.0"
        testInstrumentationRunner = if (providers.gradleProperty("physicalProbe").orNull == "true")
            "org.urlguardian.app.PhysicalProbe" else "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += setOf("arm64-v8a", "x86_64") }
    }

    signingConfigs {
        if (productionSigningConfigured) {
            create("productionRelease") {
                storeFile = productionKeystoreFile
                storePassword = productionKeystorePassword
                keyAlias = productionKeyAlias
                keyPassword = productionKeyPassword
                storeType = productionKeystoreType
            }
        }
    }

    // Full shrinking is the default. -Pinstrumentable=true adds scoped runtime
    // keeps so the release candidate can be driven by instrumentation tests;
    // that variant is for testing only and is clearly built with the property.
    val instrumentable = (providers.gradleProperty("instrumentable").orNull ?: "false").toBoolean()
    val releaseProguardFiles = if (instrumentable) {
        arrayOf(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro", "instrumentable-rules.pro")
    } else {
        arrayOf(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(*releaseProguardFiles)
            // Test-only rules for the instrumentation APK; the release APK's own
            // R8 inputs are unchanged.
            testProguardFiles("test-proguard-rules.pro")
            if (productionSigningConfigured) {
                signingConfig = signingConfigs.getByName("productionRelease")
            }
        }
        create("releaseCandidate") {
            initWith(getByName("release"))
            signingConfig = signingConfigs.getByName("debug")
            versionNameSuffix = "-rc"
            proguardFiles(*releaseProguardFiles)
            testProguardFiles("test-proguard-rules.pro")
        }
    }

    // arm64-v8a is the production target; x86_64 stays for emulator and developer
    // testing. ABI splits are opt-in because AGP cannot build an Android App Bundle
    // when multiple APKs are configured:
    //   gradlew assembleRelease bundleRelease                  -> universal APK + AAB
    //   gradlew assembleRelease -PabiSplits=true               -> per-ABI + universal APKs
    val abiSplitsEnabled = (providers.gradleProperty("abiSplits").orNull ?: "false").toBoolean()
    splits {
        abi {
            isEnable = abiSplitsEnabled
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }

    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging { resources.excludes += setOf("META-INF/INDEX.LIST", "META-INF/DEPENDENCIES") }
    // AndroidTest variants (and their R8 step) are only created for the test build
    // type. Release-candidate instrumentation therefore uses:
    //   gradlew assembleReleaseCandidate assembleReleaseCandidateAndroidTest -PtestBuildType=releaseCandidate
    testBuildType = providers.gradleProperty("testBuildType").orNull ?: "debug"

    androidResources {
        // Keep test and documentation-only assets out of the shipped APK. The app
        // reads public_suffixes.txt, tokenizer.json, urlbert_binary.onnx,
        // ti_bundle.json and the threat_intel_sha256.txt fallback at runtime.
        ignoreAssetsPattern = listOf(
            "golden_set.json", "policy_v2_golden.json", "parity_report.json",
            "feature_schema.json", "output_schema.json", "deployment_manifest.json",
            "decision_policy.json",
        ).joinToString(":")
    }
    packaging { jniLibs { useLegacyPackaging = false } }
    sourceSets {
        getByName("main").assets.srcDir("../../deployment/android/v2")
        getByName("test").resources.srcDir("../../deployment/android/v2")
        getByName("test").resources.srcDir("../../deployment/security")
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.30.0")
    implementation("org.json:json:20250517")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.microsoft.onnxruntime:onnxruntime:1.30.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

tasks.register("productionSigningStatus") {
    group = "reporting"
    description = "Reports production signing configuration presence. Never prints secrets."
    doLast {
        fun mark(value: String?) = if (!value.isNullOrBlank()) "SET" else "NOT SET"
        println("URL_GUARDIAN_KEYSTORE_PATH: ${mark(productionKeystorePath)}")
        println("URL_GUARDIAN_KEY_ALIAS: ${mark(productionKeyAlias)}")
        println("URL_GUARDIAN_KEYSTORE_PASSWORD: ${mark(productionKeystorePassword)}")
        println("URL_GUARDIAN_KEY_PASSWORD: ${mark(productionKeyPassword)}")
        println("URL_GUARDIAN_KEYSTORE_TYPE: $productionKeystoreType")
        println("keystoreFileExists: ${productionKeystoreFile?.exists() ?: false}")
        println("keystoreInsideRepository: $productionKeystoreInsideRepo")
        println("productionSigningConfigured: $productionSigningConfigured")
        if (productionSigningConfigured && !productionKeystoreInsideRepo) {
            println("releaseSigningConfig: productionRelease")
        } else {
            println("releaseSigningConfig: none (release stays unsigned)")
        }
    }
}
