package org.urlguardian.app.core

data class AnalysisTimings(
    val normalizationMs: Double, val tokenizerMs: Double, val inferenceMs: Double,
    val policyMs: Double, val totalMs: Double, val threatIntelMs: Double,
    val intelMs: Double = 0.0,
)

data class AnalysisResult(
    val normalizedUrl: String,
    val threatIntelStatus: ThreatIntelStatus,
    val benignProbability: Float,
    val phishingProbability: Float,
    val decision: EngineDecision,
    val brand: BrandAssessment,
    val shortener: ShortenerAssessment,
    val redirect: RedirectContext,
    val bundleStatus: BundleStatus,
    val modelVersion: String = "URLBERT_PHISHING_BINARY_V1 / 0.6.0",
    val snapshotVersion: String = "frozen-ti-2026-09-20 / 7,833 indicators",
    val timings: AnalysisTimings,
)

enum class DecisionEngine { V1, V2 }

class SecurityAnalyzer(
    private val normalizer: UrlNormalizer,
    private val tokenizer: ByteLevelBpeTokenizer,
    private val threatIntel: ThreatIntelIndex,
    private val model: UrlBertOnnx,
    private val brandEngine: BrandDetectionEngine = BrandDetectionEngine(BrandCatalog.EMPTY),
    private val shortenerEngine: ShortenerDetectionEngine = ShortenerDetectionEngine(ShortenerCatalog.EMPTY),
    private val redirectResolver: RedirectResolver = NoOpRedirectResolver(),
    private val bundleStatus: BundleStatus = BundleStatus.NONE,
    private val engine: DecisionEngine = DecisionEngine.V1,
) : AutoCloseable {
    fun analyze(input: String): AnalysisResult {
        val totalStart = System.nanoTime()
        val startNormalize = System.nanoTime()
        val normalized = normalizer.normalize(input)
        val normalizeEnd = System.nanoTime()
        val tiStart = System.nanoTime()
        val tiStatus = threatIntel.lookup(normalized)
        val tiEnd = System.nanoTime()
        val tokenizerStart = System.nanoTime()
        val encoding = tokenizer.encode(normalized.registrableDomain)
        val tokenizerEnd = System.nanoTime()
        val inferenceStart = System.nanoTime()
        val probabilities = model.predict(encoding)
        val inferenceEnd = System.nanoTime()
        val intelStart = System.nanoTime()
        val brand = brandEngine.assess(normalized)
        val shortener = shortenerEngine.assess(normalized)
        val redirect = redirectResolver.resolve(normalized)
        val intelEnd = System.nanoTime()
        val policyStart = System.nanoTime()
        val extracted = FeatureExtractor.extractV2(
            normalized, brand, shortener, redirect,
            threatIntelAvailable = bundleStatus.integrityOk || threatIntel.indicatorCount() > 0,
            knownMalicious = tiStatus == ThreatIntelStatus.KNOWN_MALICIOUS,
            brandCatalogAvailable = brandEngine.catalogSize > 0,
            shortenerCatalogAvailable = shortenerEngine.catalogSize > 0,
        )
        val decision = when (engine) {
            DecisionEngine.V2 -> DecisionPolicyV2.decide(probabilities[1], extracted.values, extracted.availability, tiStatus)
            DecisionEngine.V1 -> v1Decision(probabilities[1], extracted.values, tiStatus)
        }
        val policyEnd = System.nanoTime()
        fun elapsed(a: Long, b: Long) = (b - a) / 1_000_000.0
        return AnalysisResult(
            normalized.normalizedUrl, tiStatus, probabilities[0], probabilities[1], decision,
            brand, shortener, redirect, bundleStatus,
            timings = AnalysisTimings(
                elapsed(startNormalize, normalizeEnd), elapsed(tokenizerStart, tokenizerEnd),
                elapsed(inferenceStart, inferenceEnd), elapsed(policyStart, policyEnd),
                elapsed(totalStart, policyEnd), elapsed(tiStart, tiEnd), elapsed(intelStart, intelEnd),
            ),
        )
    }

    private fun v1Decision(
        phishingProbability: Float,
        features: Map<String, Double>,
        threatIntelStatus: ThreatIntelStatus,
    ): EngineDecision {
        val legacy = DecisionPolicyV1.decide(phishingProbability, features, threatIntelStatus)
        val code = when (legacy.reason) {
            "threat_intelligence_known_malicious" -> ReasonCode.KNOWN_MALICIOUS_GUARDRAIL
            "local_whitelist_hit" -> ReasonCode.WHITELIST_ALLOW
            "high_phishing_probability_with_supporting_evidence" -> ReasonCode.HIGH_PROBABILITY_WITH_EVIDENCE
            "elevated_phishing_probability" -> ReasonCode.ELEVATED_PROBABILITY
            else -> ReasonCode.LOW_RISK
        }
        return EngineDecision(legacy.risk, legacy.action, code, legacy.reason, legacy.evidenceCount, DecisionPolicyV1.VERSION)
    }

    override fun close() = model.close()
}
