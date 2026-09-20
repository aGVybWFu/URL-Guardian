package org.urlguardian.app

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.urlguardian.app.core.Action
import org.urlguardian.app.core.ByteLevelBpeTokenizer
import org.urlguardian.app.core.DecisionPolicyV1
import org.urlguardian.app.core.FeatureExtractor
import org.urlguardian.app.core.IntentLoopGuard
import org.urlguardian.app.core.PublicSuffixIndex
import org.urlguardian.app.core.Risk
import org.urlguardian.app.core.ThreatIntelIndex
import org.urlguardian.app.core.ThreatIntelStatus
import org.urlguardian.app.core.UrlBertOnnx
import org.urlguardian.app.core.UrlNormalizationException
import org.urlguardian.app.core.UrlNormalizer
import java.io.File

class DeploymentParityTest {
    private fun resource(name: String): String = checkNotNull(javaClass.classLoader?.getResource(name)).readText()
    private val golden by lazy { JSONObject(resource("golden_set.json")).getJSONArray("fixtures") }
    private val normalizer by lazy { UrlNormalizer(PublicSuffixIndex.fromText(resource("public_suffixes.txt"))) }
    private val tokenizer by lazy { ByteLevelBpeTokenizer.fromJson(resource("tokenizer.json")) }

    @Test fun normalizer_matches_all_golden_fixtures() {
        for (index in 0 until golden.length()) {
            val row = golden.getJSONObject(index)
            val actual = normalizer.normalize(row.getString("input"))
            assertEquals("fixture $index", row.getString("normalizedUrl"), actual.normalizedUrl)
            assertEquals("fixture $index", row.getString("registrableDomain"), actual.registrableDomain)
        }
    }

    @Test fun tokenizer_ids_match_all_golden_fixtures_exactly() {
        for (index in 0 until golden.length()) {
            val row = golden.getJSONObject(index)
            val actual = tokenizer.encode(row.getString("registrableDomain"))
            val expectedIds = row.getJSONArray("tokenIds").let { array -> LongArray(array.length()) { array.getLong(it) } }
            val expectedMask = row.getJSONArray("attentionMask").let { array -> LongArray(array.length()) { array.getLong(it) } }
            assertArrayEquals("ids fixture $index", expectedIds, actual.inputIds)
            assertArrayEquals("mask fixture $index", expectedMask, actual.attentionMask)
        }
    }

    @Test fun feature_extractor_matches_policy_features() {
        val expectedNames = mapOf(
            "has_ip" to "has_ip_address", "uses_https" to "is_https",
            "url_length" to "url_length", "hostname_length" to "hostname_length",
            "subdomain_count" to "subdomain_count", "digit_ratio" to "digit_ratio",
            "special_character_ratio" to "special_character_ratio", "hostname_entropy" to "hostname_entropy",
            "has_punycode" to "has_punycode", "has_at_symbol" to "has_at_symbol",
            "has_non_default_port" to "has_non_default_port", "contains_login" to "contains_login",
            "contains_verify" to "contains_verify", "contains_secure" to "contains_secure",
            "contains_account" to "contains_account", "contains_password" to "contains_password",
            "contains_payment" to "contains_payment", "contains_wallet" to "contains_wallet",
        )
        for (index in 0 until golden.length()) {
            val row = golden.getJSONObject(index)
            val expected = row.getJSONObject("features")
            val actual = FeatureExtractor.extract(normalizer.normalize(row.getString("input")))
            expectedNames.forEach { (androidName, pythonName) ->
                assertEquals("$index $androidName", expected.getDouble(pythonName), actual.getValue(androidName), 1e-9)
            }
        }
    }

    @Test fun onnx_probabilities_and_classes_match_golden_set() {
        val modelBytes = checkNotNull(javaClass.classLoader?.getResource("urlbert_binary.onnx")).readBytes()
        UrlBertOnnx(modelBytes).use { model ->
            for (index in 0 until golden.length()) {
                val row = golden.getJSONObject(index)
                val expected = row.getJSONArray("onnxProbabilities")
                val actual = model.predict(tokenizer.encode(row.getString("registrableDomain")))
                assertEquals(expected.getDouble(0), actual[0].toDouble(), 2e-5)
                assertEquals(expected.getDouble(1), actual[1].toDouble(), 2e-5)
                assertEquals(if (expected.getDouble(1) > expected.getDouble(0)) 1 else 0, if (actual[1] > actual[0]) 1 else 0)
            }
        }
    }

    @Test fun decision_policy_and_guardrail_are_exact() {
        assertEquals(Action.ALLOW, DecisionPolicyV1.decide(0.349f, emptyMap(), ThreatIntelStatus.UNKNOWN).action)
        assertEquals(Action.REVIEW, DecisionPolicyV1.decide(0.35f, emptyMap(), ThreatIntelStatus.UNKNOWN).action)
        val blocked = DecisionPolicyV1.decide(0.85f, mapOf("contains_login" to 1.0), ThreatIntelStatus.UNKNOWN)
        assertEquals(Action.BLOCK, blocked.action)
        assertEquals(Risk.DANGEROUS, blocked.risk)
        assertEquals(Action.BLOCK, DecisionPolicyV1.decide(0.0f, emptyMap(), ThreatIntelStatus.KNOWN_MALICIOUS).action)
    }

    @Test fun decision_policy_matches_all_golden_fixtures() {
        for (index in 0 until golden.length()) {
            val row = golden.getJSONObject(index)
            val features = FeatureExtractor.extract(normalizer.normalize(row.getString("input")))
            val probability = row.getJSONArray("onnxProbabilities").getDouble(1).toFloat()
            val actual = DecisionPolicyV1.decide(probability, features, ThreatIntelStatus.UNKNOWN)
            assertEquals("action $index", row.getString("expectedAction"), actual.action.name)
            assertEquals("risk $index", row.getString("expectedRisk"), actual.risk.name)
            assertEquals("reason $index", row.getString("expectedReason"), actual.reason)
        }
    }

    @Test fun intent_loop_guard_excludes_own_package() {
        val packages = IntentLoopGuard.externalPackages("org.urlguardian.app", listOf("org.urlguardian.app", "com.android.chrome"))
        assertEquals(setOf("com.android.chrome"), packages)
    }

    @Test fun threat_intelligence_distinguishes_all_statuses() {
        val digest = ThreatIntelIndex.sha256("example.com")
        val url = normalizer.normalize("https://example.com/")
        assertEquals(ThreatIntelStatus.KNOWN_MALICIOUS, ThreatIntelIndex.fromText(digest).lookup(url))
        assertEquals(ThreatIntelStatus.UNKNOWN, ThreatIntelIndex.fromText("0".repeat(64)).lookup(url))
        assertEquals(ThreatIntelStatus.UNAVAILABLE, ThreatIntelIndex.unavailable().lookup(url))
        assertEquals(ThreatIntelStatus.ERROR, ThreatIntelIndex.error().lookup(url))
    }

    @Test fun malformed_urls_are_rejected() {
        listOf("", "ftp://example.com", "https://exa mple.com", "https://example.com/%zz").forEach {
            try { normalizer.normalize(it); throw AssertionError("accepted malformed input: $it") }
            catch (_: UrlNormalizationException) { }
        }
    }

    @Test fun manifest_and_assets_are_consistent() {
        val manifest = JSONObject(resource("deployment_manifest.json"))
        assertEquals("android-v2", manifest.getString("deploymentVersion"))
        assertEquals("DecisionPolicyV1", manifest.getJSONObject("app").getString("defaultDecisionEngine"))
        assertEquals("DecisionPolicyV2", manifest.getJSONObject("app").getString("experimentalDecisionEngine"))
        assertEquals(65, manifest.getInt("goldenFixtureCount"))
        assertEquals(7833, manifest.getJSONObject("threatIntelligence").getInt("indicatorCount"))
        assertFalse(manifest.getJSONObject("ugdm").getBoolean("enabled"))
        assertTrue(manifest.getJSONObject("parity").getBoolean("passed"))
    }

    @Test fun source_and_manifest_do_not_contain_secret_assignments() {
        val root = checkNotNull(File(checkNotNull(System.getProperty("user.dir"))).parentFile)
        val candidates = File(root, "android").walkTopDown().filter {
            it.isFile && "build" !in it.toPath().map { part -> part.toString() } && it.extension in setOf("kt", "kts", "xml", "json")
        }
        val secretPattern = Regex("(?i)(api[_-]?key|auth[_-]?key|secret|token)\\s*[:=]\\s*[\"'][A-Za-z0-9_-]{20,}")
        candidates.forEach { assertFalse("possible secret in ${it.path}", secretPattern.containsMatchIn(it.readText())) }
    }

    @Test fun query_values_are_redacted_for_display() {
        assertEquals("https://example.com/path?REDACTED#REDACTED", redactQuery("https://example.com/path?password=secret#x"))
        assertEquals("https://REDACTED@example.com/path", redactQuery("https://user:secret@example.com/path"))
        assertEquals("https://REDACTED@example.com/?REDACTED", redactQuery("https://user:secret@example.com/?token=abc"))
        assertEquals("http://REDACTED@example.com:8080/x", redactQuery("http://u:p@example.com:8080/x"))
    }
}
