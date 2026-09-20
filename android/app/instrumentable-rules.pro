# Optional rules enabled with -Pinstrumentable=true.
#
# Android instrumentation APKs are minified separately and resolve application
# and runtime classes by name from the app under test, which a fully R8-hardened
# build intentionally renames or removes. This variant therefore preserves class
# names and reachability so the release candidate can be driven by the standard
# instrumentation suite.
#
# The default release/releaseCandidate builds (no property) apply full R8
# shrinking and obfuscation and are validated by the adb E2E suite instead.
# This file is test-only and must never be used for production artifacts.
-dontshrink
-dontobfuscate

-keep class org.urlguardian.app.** { *; }
-keep class kotlin.** { *; }
-keep class kotlinx.coroutines.** { *; }
-keep class androidx.compose.** { *; }
-keep class androidx.tracing.** { *; }
