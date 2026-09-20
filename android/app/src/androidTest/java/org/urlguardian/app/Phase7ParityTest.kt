package org.urlguardian.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.urlguardian.app.core.*

/** Supplemental physical parity. Debug instrumentation; never reported as RC latency. */
@RunWith(AndroidJUnit4::class)
class Phase7ParityTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private fun appAsset(name: String) = context.assets.open(name).bufferedReader().use { it.readText() }
    private fun fixture(name: String) = JSONObject(instrumentation.context.assets.open("phase7/$name").bufferedReader().use { it.readText() })
    private val normalizer by lazy { UrlNormalizer(PublicSuffixIndex.fromText(appAsset("public_suffixes.txt"))) }
    private val tokenizer by lazy { ByteLevelBpeTokenizer.fromJson(appAsset("tokenizer.json")) }

    @Test fun frozen_golden_physical_parity() {
        val rows = fixture("golden.json").getJSONArray("fixtures")
        val modelBytes = context.assets.open("urlbert_binary.onnx").use { it.readBytes() }
        UrlBertOnnx(modelBytes).use { model ->
            for (i in 0 until rows.length()) {
                val row = rows.getJSONObject(i)
                val url = normalizer.normalize(row.getString("input"))
                assertEquals(row.getString("normalizedUrl"), url.normalizedUrl)
                assertEquals(row.getString("registrableDomain"), url.registrableDomain)
                val encoded = tokenizer.encode(url.registrableDomain)
                val ids = row.getJSONArray("tokenIds"); val mask = row.getJSONArray("attentionMask")
                assertArrayEquals(LongArray(ids.length()) { ids.getLong(it) }, encoded.inputIds)
                assertArrayEquals(LongArray(mask.length()) { mask.getLong(it) }, encoded.attentionMask)
                val probability = model.predict(encoded)
                val expected = row.getJSONArray("onnxProbabilities")
                assertEquals(expected.getDouble(1), probability[1].toDouble(), 2e-5)
                val features = FeatureExtractor.extract(url)
                val actual = DecisionPolicyV1.decide(probability[1], features, ThreatIntelStatus.UNKNOWN)
                assertEquals(row.getString("expectedAction"), actual.action.name)
                assertEquals(row.getString("expectedRisk"), actual.risk.name)
                assertEquals(row.getString("expectedReason"), actual.reason)
            }
        }
        println("PHASE7_GOLDEN: normalizer=65 tokenizer=65 onnx=65 policyV1=65")
    }

    @Test fun adversarial_physical_parity_and_separate_intel_timings() {
        val bundle = TiBundle.parseVerified(appAsset("ti_bundle.json").toByteArray()).first!!
        val brand = BrandDetectionEngine(bundle.brandCatalog)
        val shortener = ShortenerDetectionEngine(bundle.shortenerCatalog)
        val corpus = fixture("adversarial.json")
        val urls = corpus.getJSONArray("urlCases")
        for (i in 0 until urls.length()) {
            val row = urls.getJSONObject(i)
            try {
                val actual = normalizer.normalize(row.getString("input"))
                assertEquals("ACCEPTED", row.getString("outcome"))
                assertEquals(row.getString("normalizedUrl"), actual.normalizedUrl)
                assertEquals(row.getString("hostname"), actual.hostname)
                assertEquals(row.getString("registrableDomain"), actual.registrableDomain)
            } catch (e: UrlNormalizationException) {
                assertNotEquals("ACCEPTED", row.getString("outcome"))
                assertEquals(row.getString("outcome") == "UNSUPPORTED_SCHEME", e is UnsupportedSchemeException)
            }
        }
        val brands = corpus.getJSONArray("brandCases")
        for (i in 0 until brands.length()) {
            val row = brands.getJSONObject(i); val a = brand.assess(normalizer.normalize(row.getString("input")))
            assertEquals(row.getBoolean("expectedDetected"), a.detected)
            assertEquals(row.getBoolean("expectedOfficialDomain"), a.officialDomain)
            assertEquals(row.getBoolean("expectedDomainMismatch"), a.domainMismatch)
            assertEquals(row.getDouble("expectedRiskScore"), a.riskScore, 1e-9)
        }
        val shorteners = corpus.getJSONArray("shortenerCases")
        for (i in 0 until shorteners.length()) {
            val row = shorteners.getJSONObject(i); val a = shortener.assess(normalizer.normalize(row.getString("input")))
            assertEquals(row.getBoolean("expectedDetected"), a.detected)
            val expectedDomain = if (row.isNull("expectedDomain")) null else row.getString("expectedDomain")
            assertEquals(expectedDomain, a.domain)
        }
        val safe = normalizer.normalize("https://google-login.example/login")
        repeat(20) { brand.assess(safe); shortener.assess(safe) }
        val bt = mutableListOf<Double>(); val st = mutableListOf<Double>()
        repeat(100) {
            var start = System.nanoTime(); brand.assess(safe); bt.add((System.nanoTime()-start)/1e6)
            start = System.nanoTime(); shortener.assess(safe); st.add((System.nanoTime()-start)/1e6)
        }
        fun stats(a: List<Double>): JSONObject {
            val s=a.sorted(); return JSONObject().put("averageMs",s.average()).put("p50Ms",s[49]).put("p95Ms",s[94]).put("minMs",s.first()).put("maxMs",s.last())
        }
        val report = JSONObject().put("build", "DEBUG_SUPPLEMENTAL_NOT_RC").put("warmupCount",20).put("measurementCount",100)
            .put("brand",stats(bt)).put("shortener",stats(st)).put("urlCases",46).put("brandCases",12).put("shortenerCases",8)
        context.filesDir.resolve("phase7_supplemental.json").writeText(report.toString(2))
        println("PHASE7_ADVERSARIAL: urls=46 brands=12 shorteners=8")
    }
}
