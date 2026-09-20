# URL Guardian R8 rules (Phase 6).
#
# Scoped keeps only. Never use a global "-keep class ** { *; }": that would
# disable shrinking and hide real compatibility problems.

# ONNX Runtime loads execution providers and JNI entry points reflectively.
-keep class ai.onnxruntime.** { *; }
-dontwarn ai.onnxruntime.**

# The org.json artifact is used directly by the TI bundle parser and the
# explainability payload helpers.
-keep class org.json.** { *; }

# AndroidX / Compose / Kotlin coroutines publish their own consumer rules.
# org.urlguardian.app classes are reachable from the manifest and from direct
# references, so no application-wide keep rule is required.

# The release-candidate app and its instrumentation APK are minified together,
# so no application-wide keep rule is needed for instrumentability.

# AndroidX Tracing is resolved by name by test infrastructure and several
# AndroidX runtime hooks; keep this single scoped namespace.
-keep class androidx.tracing.** { *; }
