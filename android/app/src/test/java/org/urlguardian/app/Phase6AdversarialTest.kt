package org.urlguardian.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.urlguardian.app.core.BrandDetectionEngine
import org.urlguardian.app.core.PublicSuffixIndex
import org.urlguardian.app.core.SchemeGuard
import org.urlguardian.app.core.SchemeOutcome
import org.urlguardian.app.core.ShortenerDetectionEngine
import org.urlguardian.app.core.TiBundle
import org.urlguardian.app.core.UnsupportedSchemeException
import org.urlguardian.app.core.UrlNormalizationException
import org.urlguardian.app.core.UrlNormalizer

class Phase6AdversarialTest {
    private fun resource(name: String): String = checkNotNull(javaClass.classLoader?.getResource(name)).readText()

    private val corpus by lazy { JSONObject(resource("adversarial_urls_v1.json")) }
    private val normalizer by lazy { UrlNormalizer(PublicSuffixIndex.fromText(resource("public_suffixes.txt"))) }
    private val bundle by lazy {
        checkNotNull(TiBundle.parse(checkNotNull(javaClass.classLoader?.getResource("ti_bundle.json")).readBytes()))
    }
    private val brandEngine by lazy { BrandDetectionEngine(bundle.brandCatalog) }
    private val shortenerEngine by lazy { ShortenerDetectionEngine(bundle.shortenerCatalog) }

    @Test fun corpus_shape_matches_python() {
        assertEquals("adversarial-url-corpus-v1", corpus.getString("corpusVersion"))
        assertTrue(corpus.getInt("urlCaseCount") >= 40)
        assertTrue(corpus.getInt("unsupportedSchemeCount") >= 7)
        assertEquals(corpus.getInt("urlCaseCount"), corpus.getJSONArray("urlCases").length())
    }

    @Test fun scheme_guard_matches_python_outcomes() {
        val cases = corpus.getJSONArray("urlCases")
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            assertEquals(
                "scheme outcome ${row.getString("id")}",
                row.getString("schemeOutcome"),
                SchemeGuard.classify(row.getString("input")).name,
            )
        }
    }

    @Test fun parser_parity_for_accepted_urls() {
        val cases = corpus.getJSONArray("urlCases")
        val expectedAccepted = (0 until cases.length()).count { cases.getJSONObject(it).getString("outcome") == "ACCEPTED" }
        var accepted = 0
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            when (row.getString("outcome")) {
                "ACCEPTED" -> {
                    accepted++
                    val actual = normalizer.normalize(row.getString("input"))
                    assertEquals("normalizedUrl ${row.getString("id")}", row.getString("normalizedUrl"), actual.normalizedUrl)
                    assertEquals("hostname ${row.getString("id")}", row.getString("hostname"), actual.hostname)
                    assertEquals("registrable ${row.getString("id")}", row.getString("registrableDomain"), actual.registrableDomain)
                }
                "UNSUPPORTED_SCHEME" -> {
                    try {
                        normalizer.normalize(row.getString("input"))
                        throw AssertionError("accepted unsupported scheme: ${row.getString("id")}")
                    } catch (_: UnsupportedSchemeException) { }
                }
                "MALFORMED" -> {
                    try {
                        normalizer.normalize(row.getString("input"))
                        throw AssertionError("accepted malformed input: ${row.getString("id")}")
                    } catch (exception: UrlNormalizationException) {
                        assertFalse(
                            "expected a plain malformed rejection for ${row.getString("id")}",
                            exception is UnsupportedSchemeException,
                        )
                    }
                }
            }
        }
        assertTrue(expectedAccepted >= 25)
        assertEquals(expectedAccepted, accepted)
    }

    @Test fun unsupported_schemes_are_explicit_and_never_openable() {
        for (raw in listOf("javascript:alert(1)", "file:///etc/passwd", "content://x/1", "intent://x/#Intent;end", "data:text/html,x", "ftp://example.com/f", "ws://example.com/")) {
            assertEquals(SchemeOutcome.UNSUPPORTED_SCHEME, SchemeGuard.classify(raw))
            try {
                normalizer.normalize(raw)
                throw AssertionError("accepted unsupported scheme: $raw")
            } catch (_: UnsupportedSchemeException) { }
        }
    }

    @Test fun brand_cases_match_python_engine() {
        val cases = corpus.getJSONArray("brandCases")
        assertTrue(cases.length() >= 10)
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            val actual = brandEngine.assess(normalizer.normalize(row.getString("input")))
            assertEquals("detected ${row.getString("input")}", row.getBoolean("expectedDetected"), actual.detected)
            assertEquals("official ${row.getString("input")}", row.getBoolean("expectedOfficialDomain"), actual.officialDomain)
            assertEquals("mismatch ${row.getString("input")}", row.getBoolean("expectedDomainMismatch"), actual.domainMismatch)
            assertEquals("score ${row.getString("input")}", row.getDouble("expectedRiskScore"), actual.riskScore, 1e-9)
            val expectedBrands = row.getJSONArray("expectedBrands")
            val expected = (0 until expectedBrands.length()).map { i ->
                val item = expectedBrands.getJSONObject(i)
                listOf(item.getString("brandId"), item.getString("location"), item.getBoolean("confusable").toString()).joinToString("|")
            }
            val actualBrands = actual.brands
                .map { listOf(it.brandId, it.location, it.confusable.toString()).joinToString("|") }
                .sorted()
            assertEquals("brands ${row.getString("input")}", expected.sorted(), actualBrands)
        }
    }

    @Test fun shortener_cases_match_python_engine() {
        val cases = corpus.getJSONArray("shortenerCases")
        assertTrue(cases.length() >= 8)
        for (index in 0 until cases.length()) {
            val row = cases.getJSONObject(index)
            val actual = shortenerEngine.assess(normalizer.normalize(row.getString("input")))
            assertEquals("detected ${row.getString("input")}", row.getBoolean("expectedDetected"), actual.detected)
            assertEquals("domain ${row.getString("input")}", row.optString("expectedDomain", ""), actual.domain.orEmpty())
        }
    }
}
