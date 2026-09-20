package org.urlguardian.app.core

import android.content.Context

object AnalyzerFactory {
    /**
     * Production entry point. The shipped default decision engine is
     * `DecisionPolicyV1`; Phase 5 brand, shortener and redirect evidence is still
     * computed and displayed, but `DecisionPolicyV2` is experimental only.
     */
    fun create(
        context: Context,
        redirectResolver: RedirectResolver = NoOpRedirectResolver(),
        engine: DecisionEngine = DecisionEngine.V1,
    ): Pair<SecurityAnalyzer, BundleStatus> {
        fun asset(name: String) = context.assets.open(name).bufferedReader().use { it.readText() }
        val suffixes = PublicSuffixIndex.fromText(asset("public_suffixes.txt"))
        val tokenizer = ByteLevelBpeTokenizer.fromJson(asset("tokenizer.json"))
        val model = UrlBertOnnx(context.assets.open("urlbert_binary.onnx").use { it.readBytes() })
        val intelState = TiBundleStore(context).load()
        val bundle = intelState.bundle
        val threatIntel = if (bundle != null) {
            ThreatIntelIndex.fromDigests(bundle.indicatorDigests)
        } else {
            ThreatIntelIndex.fromText(asset("threat_intel_sha256.txt"))
        }
        val analyzer = SecurityAnalyzer(
            UrlNormalizer(suffixes),
            tokenizer,
            threatIntel,
            model,
            brandEngine = BrandDetectionEngine(bundle?.brandCatalog ?: BrandCatalog.EMPTY),
            shortenerEngine = ShortenerDetectionEngine(bundle?.shortenerCatalog ?: ShortenerCatalog.EMPTY),
            redirectResolver = redirectResolver,
            bundleStatus = intelState.status,
            engine = engine,
        )
        return analyzer to intelState.status
    }

    /** Developer / research mode only: selects the experimental DecisionPolicyV2. */
    fun createResearch(
        context: Context,
        redirectResolver: RedirectResolver = NoOpRedirectResolver(),
    ): Pair<SecurityAnalyzer, BundleStatus> = create(context, redirectResolver, DecisionEngine.V2)
}
