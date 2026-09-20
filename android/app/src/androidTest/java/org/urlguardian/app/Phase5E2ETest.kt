package org.urlguardian.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.urlguardian.app.core.AnalyzerFactory
import org.urlguardian.app.core.BundleSource
import org.urlguardian.app.core.CanonicalJson
import org.urlguardian.app.core.FixtureRedirectResolver
import org.urlguardian.app.core.REDIRECT_OBSERVED
import org.urlguardian.app.core.RedirectContext
import org.urlguardian.app.core.StalenessStatus
import org.urlguardian.app.core.TiBundle
import org.urlguardian.app.core.TiBundleStore
import java.io.File

@RunWith(AndroidJUnit4::class)
class Phase5E2ETest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val store = TiBundleStore(context)

    @After fun cleanUpImportedBundles() {
        listOf(
            File(context.filesDir, TiBundleStore.ACTIVE_NAME),
            File(context.filesDir, TiBundleStore.PENDING_NAME),
            File(context.filesDir, TiBundleStore.BACKUP_NAME),
            File(context.filesDir, TiBundleStore.PREVIOUS_NAME),
            File(context.filesDir, TiBundleStore.STAGING_NAME),
            store.candidateFile(),
        ).forEach { it?.takeIf { file -> file.exists() }?.delete() }
    }

    private fun assetBundleBytes(): ByteArray =
        context.assets.open(TiBundleStore.ASSET_NAME).use { it.readBytes() }

    private fun buildModifiedBundle(extraDigest: String): ByteArray {
        val root = JSONObject(String(assetBundleBytes(), Charsets.UTF_8))
        val payload = root.getJSONObject("payload")
        val threatIntel = payload.getJSONObject("threatIntel")
        val digests = threatIntel.getJSONArray("indicatorDigests")
        val sorted = ((0 until digests.length()).map { digests.getString(it) } + extraDigest).sorted()
        val array = org.json.JSONArray()
        sorted.forEach { array.put(it) }
        threatIntel.put("indicatorDigests", array)
        threatIntel.put("indicatorCount", sorted.size)
        val digest = TiBundle.sha256Hex(CanonicalJson.stringify(payload).toByteArray(Charsets.US_ASCII))
        root.getJSONObject("integrity").put("canonicalDigest", digest)
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    @Test fun asset_bundle_loads_with_integrity_and_catalogs() {
        val (analyzer, status) = AnalyzerFactory.create(context)
        analyzer.use {
            assertEquals(BundleSource.ASSET, status.source)
            assertTrue(status.integrityOk)
            assertEquals(7833, status.indicatorCount)
            assertEquals(54, status.brandCount)
            assertEquals(26, status.shortenerCount)
            assertEquals("ti-2026-09-20", status.snapshotId)
            assertEquals(StalenessStatus.FRESH, status.staleness)
            assertEquals(0L, status.ageDays)
        }
    }

    @Test fun rollback_to_previous_bundle_restores_it_and_keeps_the_newer_as_previous() {
        val digestA = TiBundle.sha256Hex("rollback-a.example".toByteArray(Charsets.UTF_8))
        val digestB = TiBundle.sha256Hex("rollback-b.example".toByteArray(Charsets.UTF_8))
        assertEquals(BundleSource.IMPORTED, store.importBytes(buildModifiedBundle(digestA)).source)
        assertTrue(store.load().bundle!!.indicatorDigests.contains(digestA))
        assertEquals(BundleSource.IMPORTED, store.importBytes(buildModifiedBundle(digestB)).source)
        val before = store.load()
        assertTrue(before.bundle!!.indicatorDigests.contains(digestB))
        assertTrue(before.status.hasPrevious)
        val rollback = store.rollbackToPrevious()
        assertEquals(BundleSource.ROLLED_BACK, rollback.source)
        val after = store.load()
        assertTrue(after.bundle!!.indicatorDigests.contains(digestA))
        assertFalse(after.bundle!!.indicatorDigests.contains(digestB))
        assertTrue(after.status.hasPrevious)
        assertEquals("ti-2026-09-20", after.status.snapshotId)
    }

    @Test fun valid_bundle_import_is_atomic_and_activates() {
        val extra = TiBundle.sha256Hex("imported.example".toByteArray(Charsets.UTF_8))
        val status = store.importBytes(buildModifiedBundle(extra))
        assertEquals(BundleSource.IMPORTED, status.source)
        assertTrue(status.integrityOk)
        assertEquals(7834, status.indicatorCount)
        val loaded = store.load()
        assertEquals(BundleSource.IMPORTED, loaded.status.source)
        assertTrue(loaded.bundle!!.indicatorDigests.contains(extra))
    }

    @Test fun corrupted_bundle_is_rejected_and_previous_bundle_rolls_back() {
        val extra = TiBundle.sha256Hex("rolled-back.example".toByteArray(Charsets.UTF_8))
        assertEquals(BundleSource.IMPORTED, store.importBytes(buildModifiedBundle(extra)).source)
        val evilDigest = TiBundle.sha256Hex("evil.example".toByteArray(Charsets.UTF_8))
        val corrupted = buildModifiedBundle(evilDigest)
        corrupted[corrupted.size / 2] = 'x'.code.toByte()
        val rejected = store.importBytes(corrupted)
        assertFalse(rejected.integrityOk)
        assertTrue(rejected.source != BundleSource.IMPORTED)
        val loaded = store.load()
        assertEquals(BundleSource.IMPORTED, loaded.status.source)
        assertTrue(loaded.bundle!!.indicatorDigests.contains(extra))
        assertFalse(loaded.bundle!!.indicatorDigests.contains(evilDigest))
    }

    @Test fun imported_indicator_triggers_guardrail_end_to_end() {
        val digest = TiBundle.sha256Hex("malicious.example".toByteArray(Charsets.UTF_8))
        assertEquals(BundleSource.IMPORTED, store.importBytes(buildModifiedBundle(digest)).source)
        val (analyzer, _) = AnalyzerFactory.create(context)
        analyzer.use {
            val result = it.analyze("https://malicious.example/")
            assertEquals("BLOCK", result.decision.action.name)
            assertEquals("KNOWN_MALICIOUS_GUARDRAIL", result.decision.reasonCode.code)
        }
    }

    @Test fun default_engine_is_v1_on_device_with_phase5_evidence_computed() {
        val (analyzer, _) = AnalyzerFactory.create(context)
        analyzer.use {
            assertEquals("DecisionPolicyV1", it.analyze("https://example.com/").decision.engineVersion)
            val brandReview = it.analyze("https://paypal.com.evil.com/")
            assertTrue(brandReview.brand.domainMismatch)
            assertEquals("ALLOW", brandReview.decision.action.name)
            assertEquals("LOW_RISK", brandReview.decision.reasonCode.code)
            val brandBlock = it.analyze("https://paypal-login.com/")
            assertEquals("BLOCK", brandBlock.decision.action.name)
            assertEquals("HIGH_PROBABILITY_WITH_EVIDENCE", brandBlock.decision.reasonCode.code)
            val official = it.analyze("https://www.paypal.com/login")
            assertTrue(official.brand.officialDomain)
            assertEquals("REVIEW", official.decision.action.name)
            assertEquals("ELEVATED_PROBABILITY", official.decision.reasonCode.code)
            val shortener = it.analyze("https://bit.ly/abc123")
            assertTrue(shortener.shortener.detected)
            assertEquals("ALLOW", shortener.decision.action.name)
            assertEquals("LOW_RISK", shortener.decision.reasonCode.code)
        }
    }

    @Test fun research_mode_selects_experimental_v2_on_device() {
        val (analyzer, _) = AnalyzerFactory.createResearch(context)
        analyzer.use {
            assertEquals("DecisionPolicyV2", it.analyze("https://example.com/").decision.engineVersion)
            val brandReview = it.analyze("https://paypal.com.evil.com/")
            assertEquals("REVIEW", brandReview.decision.action.name)
            assertEquals("BRAND_IMPERSONATION_REVIEW", brandReview.decision.reasonCode.code)
            val brandBlock = it.analyze("https://paypal-login.com/")
            assertEquals("BLOCK", brandBlock.decision.action.name)
            assertEquals("BRAND_IMPERSONATION_BLOCK", brandBlock.decision.reasonCode.code)
            val official = it.analyze("https://www.paypal.com/login")
            assertEquals("ALLOW", official.decision.action.name)
            assertEquals("OFFICIAL_BRAND_DOMAIN_ALLOW", official.decision.reasonCode.code)
            val shortener = it.analyze("https://bit.ly/abc123")
            assertEquals("REVIEW", shortener.decision.action.name)
            assertEquals("SHORTENER_REVIEW", shortener.decision.reasonCode.code)
        }
    }

    @Test fun observed_cross_domain_redirect_reviews_with_fixture_resolver() {
        val url = "https://example.com/"
        val resolver = FixtureRedirectResolver(
            mapOf(url to RedirectContext(REDIRECT_OBSERVED, redirectCount = 2, crossDomainRedirect = true, finalHostname = "evil.example"))
        )
        val (analyzer, _) = AnalyzerFactory.createResearch(context, resolver)
        analyzer.use {
            val result = it.analyze(url)
            assertEquals("REVIEW", result.decision.action.name)
            assertEquals("CROSS_DOMAIN_REDIRECT_REVIEW", result.decision.reasonCode.code)
            assertTrue(result.redirect.observed)
        }
    }

    @Test fun noop_resolver_never_observes_redirects() {
        val (analyzer, _) = AnalyzerFactory.create(context)
        analyzer.use {
            val result = it.analyze("https://example.com/")
            assertFalse(result.redirect.observed)
            assertEquals("ALLOW", result.decision.action.name)
            assertEquals("LOW_RISK", result.decision.reasonCode.code)
        }
    }
}
