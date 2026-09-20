package org.urlguardian.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.urlguardian.app.core.ByteLevelBpeTokenizer
import org.urlguardian.app.core.PublicSuffixIndex
import org.urlguardian.app.core.SecurityAnalyzer
import org.urlguardian.app.core.ThreatIntelIndex
import org.urlguardian.app.core.UrlBertOnnx
import org.urlguardian.app.core.UrlNormalizer

@RunWith(AndroidJUnit4::class)
class LaunchTest {
    @Test fun app_launches_without_network_or_webview() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity -> check(!activity.isFinishing) }
        }
    }

    @Test fun safe_action_view_is_intercepted_without_network_permission() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val permissions = context.packageManager.getPackageInfo(
            context.packageName, PackageManager.GET_PERMISSIONS,
        ).requestedPermissions?.toSet().orEmpty()
        assertFalse(Manifest.permission.INTERNET in permissions)
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/")).setPackage(context.packageName)
        ActivityScenario.launch<MainActivity>(intent).use { scenario ->
            scenario.onActivity { assertTrue(!it.isFinishing) }
        }
    }

    @Test fun benchmark_offline_pipeline() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val (analyzer, _) = org.urlguardian.app.core.AnalyzerFactory.create(context)
        repeat(3) { analyzer.analyze("https://example.com/warmup") }
        var peakPssKb = 0L
        val results = (0 until 30).map {
            val timing = analyzer.analyze("https://sub$it.example.com/login?id=REDACTED").timings
            peakPssKb = maxOf(peakPssKb, android.os.Debug.getPss().toLong())
            timing
        }
        fun percentile(values: List<Double>, fraction: Double): Double {
            val sorted = values.sorted()
            return sorted[((sorted.size - 1) * fraction).toInt()]
        }
        fun stats(values: List<Double>) = JSONObject()
            .put("averageMs", values.average()).put("p50Ms", percentile(values, 0.50)).put("p95Ms", percentile(values, 0.95))
        val runtime = Runtime.getRuntime()
        val report = JSONObject()
            .put("runs", results.size)
            .put("normalization", stats(results.map { it.normalizationMs }))
            .put("tokenizer", stats(results.map { it.tokenizerMs }))
            .put("inference", stats(results.map { it.inferenceMs }))
            .put("policy", stats(results.map { it.policyMs }))
            .put("threatIntelLookup", stats(results.map { it.threatIntelMs }))
            .put("intel", stats(results.map { it.intelMs }))
            .put("total", stats(results.map { it.totalMs }))
            .put("runtimeUsedMemoryBytes", runtime.totalMemory() - runtime.freeMemory())
            .put("peakProcessPssKb", peakPssKb)
            .put("device", android.os.Build.MODEL)
            .put("abi", android.os.Build.SUPPORTED_ABIS.joinToString(","))
            .put("androidApi", android.os.Build.VERSION.SDK_INT)
        context.filesDir.resolve("android_benchmark.json").writeText(report.toString(2))
        println("URL_GUARDIAN_BENCHMARK=${report}")
    }
}
