package org.urlguardian.app

import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.urlguardian.app.core.CanonicalJson
import org.urlguardian.app.core.TiBundle
import org.urlguardian.app.core.TiBundleStore
import java.io.File

@RunWith(AndroidJUnit4::class)
class Phase5UiE2ETest {
    @get:Rule val composeRule = createEmptyComposeRule()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val store = TiBundleStore(context)

    @After fun cleanUpImportedBundles() {
        listOf(
            File(context.filesDir, TiBundleStore.ACTIVE_NAME),
            File(context.filesDir, TiBundleStore.PENDING_NAME),
            File(context.filesDir, TiBundleStore.BACKUP_NAME),
            File(context.filesDir, TiBundleStore.STAGING_NAME),
            store.candidateFile(),
        ).forEach { it?.takeIf { file -> file.exists() }?.delete() }
    }

    private fun launchAndAwait(url: String): ActivityScenario<MainActivity> {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).setPackage(context.packageName)
        val scenario = ActivityScenario.launch<MainActivity>(intent)
        scenario.onActivity { check(!it.isFinishing) }
        composeRule.waitUntil(timeoutMillis = 60_000) {
            composeRule.onAllNodesWithText("原因代碼：", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        return scenario
    }

    private fun analyzeAndExpect(url: String, expectedReason: String, evidenceText: String? = null) {
        launchAndAwait(url).use {
            composeRule.onNodeWithText("原因代碼：$expectedReason").assertExists()
            if (evidenceText != null) {
                composeRule.onNodeWithText(evidenceText, substring = true).assertExists()
            }
        }
    }

    private fun importBundleWithDigest(rawValue: String) {
        val bytes = context.assets.open(TiBundleStore.ASSET_NAME).use { it.readBytes() }
        val root = JSONObject(String(bytes, Charsets.UTF_8))
        val payload = root.getJSONObject("payload")
        val threatIntel = payload.getJSONObject("threatIntel")
        val digests = threatIntel.getJSONArray("indicatorDigests")
        val sorted = ((0 until digests.length()).map { digests.getString(it) } + TiBundle.sha256Hex(rawValue.toByteArray(Charsets.UTF_8))).sorted()
        val array = org.json.JSONArray()
        sorted.forEach { array.put(it) }
        threatIntel.put("indicatorDigests", array)
        threatIntel.put("indicatorCount", sorted.size)
        root.getJSONObject("integrity").put(
            "canonicalDigest",
            TiBundle.sha256Hex(CanonicalJson.stringify(payload).toByteArray(Charsets.US_ASCII)),
        )
        val status = store.importBytes(root.toString().toByteArray(Charsets.UTF_8))
        check(status.integrityOk) { "bundle import failed: ${status.lastError}" }
    }

    @Test fun https_safe_url_shows_allow_low_risk() {
        analyzeAndExpect("https://example.com/", "LOW_RISK")
    }

    @Test fun http_url_is_accepted_and_analyzed() {
        analyzeAndExpect("http://example.com/", "LOW_RISK")
    }

    @Test fun default_policy_allows_low_probability_shortener_and_shows_evidence() {
        analyzeAndExpect("https://bit.ly/abc123", "LOW_RISK", "短網址：是（bit.ly）")
    }

    @Test fun default_policy_shows_brand_mismatch_evidence() {
        analyzeAndExpect("https://paypal.com.evil.com/", "LOW_RISK", "品牌比對：網域不符")
    }

    @Test fun default_policy_blocks_brand_mismatch_with_high_probability() {
        analyzeAndExpect("https://paypal-login.com/", "HIGH_PROBABILITY_WITH_EVIDENCE")
    }

    @Test fun default_policy_reviews_official_brand_domain_and_shows_evidence() {
        analyzeAndExpect("https://www.paypal.com/login", "ELEVATED_PROBABILITY", "品牌官方網域")
    }

    @Test fun imported_indicator_shows_block_guardrail() {
        importBundleWithDigest("malicious.example")
        analyzeAndExpect("https://malicious.example/", "KNOWN_MALICIOUS_GUARDRAIL")
    }

    @Test fun bundle_status_line_is_visible() {
        launchAndAwait("https://example.com/").use {
            composeRule.onNodeWithText("情資包：ti-bundle-v1", substring = true).assertExists()
        }
    }

    @Test fun app_restart_reuses_imported_bundle() {
        importBundleWithDigest("restart.example")
        analyzeAndExpect("https://restart.example/", "KNOWN_MALICIOUS_GUARDRAIL")
        analyzeAndExpect("https://restart.example/", "KNOWN_MALICIOUS_GUARDRAIL")
    }

    @Test fun manual_input_analysis_without_intent() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { check(!it.isFinishing) }
            composeRule.onNodeWithText("在裝置上分析網址。結果是風險提示，不是安全保證。").assertExists()
            composeRule.onNodeWithText("分析網址").assertExists()
        }
    }
}
