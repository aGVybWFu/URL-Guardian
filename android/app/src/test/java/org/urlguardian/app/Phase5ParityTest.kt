package org.urlguardian.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.urlguardian.app.core.BrandDetectionEngine
import org.urlguardian.app.core.CanonicalJson
import org.urlguardian.app.core.DecisionPolicyV1
import org.urlguardian.app.core.DecisionPolicyV2
import org.urlguardian.app.core.FeatureExtractor
import org.urlguardian.app.core.PublicSuffixIndex
import org.urlguardian.app.core.ShortenerDetectionEngine
import org.urlguardian.app.core.ThreatIntelStatus
import org.urlguardian.app.core.TiBundle
import org.urlguardian.app.core.UrlNormalizer

class Phase5ParityTest {
    private fun resource(name: String): String = checkNotNull(javaClass.classLoader?.getResource(name)).readText()

    private val bundleBytes by lazy { checkNotNull(javaClass.classLoader?.getResource("ti_bundle.json")).readBytes() }
    private val bundle by lazy { checkNotNull(TiBundle.parse(bundleBytes)) }
    private val parity by lazy { JSONObject(resource("policy_v2_golden.json")) }
    private val golden by lazy { JSONObject(resource("golden_set.json")).getJSONArray("fixtures") }
    private val normalizer by lazy { UrlNormalizer(PublicSuffixIndex.fromText(resource("public_suffixes.txt"))) }
    private val brandEngine by lazy { BrandDetectionEngine(bundle.brandCatalog) }
    private val shortenerEngine by lazy { ShortenerDetectionEngine(bundle.shortenerCatalog) }

    @Test fun bundle_integrity_verifies_and_counts_match_manifest() {
        val verification = TiBundle.verify(bundleBytes)
        assertTrue(verification.reason, verification.ok)
        assertEquals(7833, bundle.indicatorDigests.size)
        assertEquals(54, bundle.brandCatalog.entries.size)
        assertEquals(26, bundle.shortenerCatalog.domains.size)
        val manifest = JSONObject(resource("deployment_manifest.json")).getJSONObject("intelligenceBundle")
        assertEquals(7833, manifest.getInt("indicatorCount"))
        assertEquals(verification.digest, manifest.getString("canonicalDigest"))
        assertEquals(TiBundle.sha256Hex(bundleBytes), manifest.getString("sha256"))
    }

    @Test fun tampered_bundle_is_rejected() {
        val text = String(bundleBytes, Charsets.UTF_8).replace("paypal", "paypa1")
        val verification = TiBundle.verify(text.toByteArray(Charsets.UTF_8))
        assertFalse(verification.ok)
        assertEquals("integrity_digest_mismatch", verification.reason)
    }

    @Test fun truncated_bundle_is_rejected() {
        val verification = TiBundle.verify(bundleBytes.copyOfRange(0, 128))
        assertFalse(verification.ok)
        assertEquals("bundle_not_json", verification.reason)
    }

    @Test fun canonical_json_is_deterministic() {
        val payload = JSONObject("""{"b":1,"a":{"d":[1,2],"c":"x"}}""")
        assertEquals("""{"a":{"c":"x","d":[1,2]},"b":1}""", CanonicalJson.stringify(payload))
    }

    @Test fun brand_cases_match_python_parity_corpus() {
        val cases = parity.getJSONArray("brandCases")
        assertTrue(cases.length() >= 10)
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            val actual = brandEngine.assess(normalizer.normalize(row.getString("input")))
            assertEquals("detected $index", row.getBoolean("expectedDetected"), actual.detected)
            assertEquals("official $index", row.getBoolean("expectedOfficialDomain"), actual.officialDomain)
            assertEquals("mismatch $index", row.getBoolean("expectedDomainMismatch"), actual.domainMismatch)
            assertEquals("score $index", row.getDouble("expectedRiskScore"), actual.riskScore, 1e-9)
        }
    }

    @Test fun shortener_cases_match_python_parity_corpus() {
        val cases = parity.getJSONArray("shortenerCases")
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            val actual = shortenerEngine.assess(normalizer.normalize(row.getString("input")))
            assertEquals("detected $index", row.getBoolean("expectedDetected"), actual.detected)
            assertEquals("domain $index", row.optString("expectedDomain", ""), actual.domain.orEmpty())
        }
    }

    @Test fun decision_cases_match_python_parity_corpus() {
        val cases = parity.getJSONArray("decisionCases")
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            val featuresJson = row.getJSONObject("features")
            val availabilityJson = row.getJSONObject("availability")
            val features = featuresJson.keys().asSequence().associateWith { featuresJson.getDouble(it) }
            val availability = availabilityJson.keys().asSequence().associateWith { availabilityJson.getBoolean(it) }
            val actual = DecisionPolicyV2.decide(
                features["phishing_probability"]?.toFloat() ?: 0f, features, availability, ThreatIntelStatus.UNKNOWN,
            )
            assertEquals("action $index", row.getString("expectedAction"), actual.action.name)
            assertEquals("risk $index", row.getString("expectedRisk"), actual.risk.name)
            assertEquals("reason $index", row.getString("expectedReasonCode"), actual.reasonCode.code)
        }
    }

    @Test fun frozen_fixture_decisions_match_python_policy_v2() {
        val fixtures = parity.getJSONArray("fixtures")
        assertEquals(65, fixtures.length())
        val names = mapOf(
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
        for (index in 0 until fixtures.length()) {
            val expected = fixtures.getJSONObject(index)
            val goldenRow = golden.getJSONObject(index)
            val url = normalizer.normalize(goldenRow.getString("input"))
            val pythonFeatures = goldenRow.getJSONObject("features")
            val brand = brandEngine.assess(url)
            val shortener = shortenerEngine.assess(url)
            val values = FeatureExtractor.extract(url).toMutableMap()
            names.forEach { (androidName, pythonName) ->
                values[androidName] = pythonFeatures.getDouble(pythonName)
            }
            values.putAll(brand.toFeatures())
            values.putAll(shortener.toFeatures())
            values["known_malicious"] = 0.0
            val availability = FeatureExtractor.alwaysAvailable.associateWith { true }.toMutableMap()
            availability["known_malicious"] = true
            brand.availability().forEach { (name, available) -> availability[name] = available }
            shortener.availability().forEach { (name, available) -> availability[name] = available }
            availability["cross_domain_redirect"] = false
            availability["redirect_count"] = false
            availability["whitelist_hit"] = false
            val probability = goldenRow.getJSONArray("onnxProbabilities").getDouble(1).toFloat()
            val actual = DecisionPolicyV2.decide(probability, values, availability, ThreatIntelStatus.UNKNOWN)
            assertEquals("action $index", expected.getString("expectedAction"), actual.action.name)
            assertEquals("risk $index", expected.getString("expectedRisk"), actual.risk.name)
            assertEquals("reason $index", expected.getString("expectedReasonCode"), actual.reasonCode.code)
            assertEquals("brand $index", expected.getBoolean("brandDetected"), brand.detected)
            assertEquals("official $index", expected.getBoolean("brandOfficialDomain"), brand.officialDomain)
            assertEquals("shortener $index", expected.getBoolean("shortenerDetected"), shortener.detected)
        }
    }

    @Test fun official_brand_domain_is_protected_end_to_end() {
        val url = normalizer.normalize("https://www.paypal.com/login")
        val brand = brandEngine.assess(url)
        assertTrue(brand.officialDomain)
        val decision = DecisionPolicyV2.decide(
            0.10f,
            FeatureExtractor.extract(url) + brand.toFeatures(),
            FeatureExtractor.alwaysAvailable.associateWith { true } + brand.availability(),
            ThreatIntelStatus.UNKNOWN,
        )
        assertEquals("ALLOW", decision.action.name)
        assertEquals("OFFICIAL_BRAND_DOMAIN_ALLOW", decision.reasonCode.code)
    }

    @Test fun brand_mismatch_reviews_or_blocks() {
        val url = normalizer.normalize("https://paypal-login.com/")
        val brand = brandEngine.assess(url)
        assertTrue(brand.domainMismatch)
        val review = DecisionPolicyV2.decide(
            0.10f,
            FeatureExtractor.extract(url) + brand.toFeatures(),
            FeatureExtractor.alwaysAvailable.associateWith { true } + brand.availability(),
            ThreatIntelStatus.UNKNOWN,
        )
        assertEquals("REVIEW", review.action.name)
        assertEquals("BRAND_IMPERSONATION_REVIEW", review.reasonCode.code)
        val block = DecisionPolicyV2.decide(
            0.90f,
            FeatureExtractor.extract(url) + brand.toFeatures(),
            FeatureExtractor.alwaysAvailable.associateWith { true } + brand.availability(),
            ThreatIntelStatus.UNKNOWN,
        )
        assertEquals("BLOCK", block.action.name)
        assertEquals("BRAND_IMPERSONATION_BLOCK", block.reasonCode.code)
    }

    @Test fun shortener_alone_never_blocks() {
        val url = normalizer.normalize("https://bit.ly/abc123")
        val shortener = shortenerEngine.assess(url)
        assertTrue(shortener.detected)
        val decision = DecisionPolicyV2.decide(
            0.05f,
            FeatureExtractor.extract(url) + shortener.toFeatures(),
            FeatureExtractor.alwaysAvailable.associateWith { true } + shortener.availability(),
            ThreatIntelStatus.UNKNOWN,
        )
        assertEquals("REVIEW", decision.action.name)
        assertEquals("SHORTENER_REVIEW", decision.reasonCode.code)
    }

    @Test fun v1_policy_is_immutable_and_still_available() {
        assertEquals("DecisionPolicyV1", DecisionPolicyV1.VERSION)
        assertEquals(0.35f, DecisionPolicyV1.REVIEW_AT)
        assertEquals(0.85f, DecisionPolicyV1.BLOCK_AT)
        val decision = DecisionPolicyV1.decide(0.0f, emptyMap(), ThreatIntelStatus.KNOWN_MALICIOUS)
        assertEquals("BLOCK", decision.action.name)
        assertEquals("threat_intelligence_known_malicious", decision.reason)
    }
}
