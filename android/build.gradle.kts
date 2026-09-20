plugins {
    id("com.android.application") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.2.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.21" apply false
}

// Windows workaround: Gradle writes the JVM test worker classpath argfile as UTF-8, but the
// JDK launcher reads @argfile bytes using the active ANSI code page. When the repository path
// contains non-ASCII characters (e.g. this workspace), every classpath entry under the project
// directory is corrupted and the test worker fails with ClassNotFoundException. Relocating all
// build directories to an ASCII path removes non-ASCII entries from the worker classpath.
val projectPathHasNonAscii = rootDir.absolutePath.any { it.code > 127 }
val asciiBuildRoot = File(System.getProperty("user.home"), "ug-build/URLGuardianAndroid")

if (projectPathHasNonAscii) {
    allprojects {
        val projectDirName = if (path == ":") "root" else path.removePrefix(":").replace(':', '-')
        layout.buildDirectory.set(File(asciiBuildRoot, projectDirName))
    }
    logger.lifecycle("Non-ASCII project path detected; build directories redirected to $asciiBuildRoot")
}
