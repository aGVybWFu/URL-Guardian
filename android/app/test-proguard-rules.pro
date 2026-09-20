# Extra rules for the instrumentation test APK of the release-candidate build.
# These annotations are compile-time only and are not present at runtime.
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.MustBeClosed
