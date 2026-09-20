package org.urlguardian.app.core

data class BrandMatch(
    val brandId: String,
    val matchedAlias: String,
    val location: String,
    val confusable: Boolean,
)

data class BrandAssessment(
    val detected: Boolean,
    val officialDomain: Boolean,
    val domainMismatch: Boolean,
    val riskScore: Double,
    val brands: List<BrandMatch>,
) {
    fun toFeatures(): Map<String, Double> = mapOf(
        "brand_detected" to if (detected) 1.0 else 0.0,
        "brand_domain_mismatch" to if (domainMismatch) 1.0 else 0.0,
        "brand_risk_score" to riskScore,
    )

    fun availability(): Map<String, Boolean> = mapOf(
        "brand_detected" to true, "brand_domain_mismatch" to true, "brand_risk_score" to true,
    )

    companion object {
        val NONE = BrandAssessment(false, false, false, 0.0, emptyList())
    }
}

class BrandDetectionEngine(private val catalog: BrandCatalog) {
    val catalogSize: Int get() = catalog.entries.size

    private val variants: Map<String, Set<String>> = catalog.entries.associate { entry ->
        entry.brandId to entry.aliases.flatMap { Confusables.labelTokens(it) }.toSet()
    }

    fun assess(url: NormalizedUrl): BrandAssessment {
        val official = catalog.entries.firstOrNull { entry ->
            entry.canonicalDomains.any { domain ->
                url.registrableDomain == domain || url.hostname == domain || url.hostname.endsWith(".$domain")
            }
        }
        if (official != null) {
            return BrandAssessment(
                detected = true,
                officialDomain = true,
                domainMismatch = false,
                riskScore = 0.0,
                brands = listOf(BrandMatch(official.brandId, official.aliases.firstOrNull().orEmpty(), LOCATION_REGISTRABLE, false)),
            )
        }
        val labels = url.hostname.split('.').filter { it.isNotEmpty() }
        val decoded = labels.map { Confusables.idnaDecode(it) }
        val registrableLabel = url.registrableDomain.split('.').firstOrNull().orEmpty()
        val textTokens = Confusables.labelTokens(url.path + " " + url.query)
        val labelTokenSets = labels.indices.map {
            Confusables.labelTokens(decoded[it]) + Confusables.labelTokens(labels[it])
        }
        val labelConfusable = labels.indices.map {
            decoded[it] != labels[it] || Confusables.looksConfusable(labels[it])
        }
        val labelIsRegistrable = labels.map { it == registrableLabel }

        val matches = mutableListOf<BrandMatch>()
        var riskScore = 0.0
        var hostnameMatch = false

        for (entry in catalog.entries) {
            val entryVariants = variants[entry.brandId].orEmpty()
            if (entryVariants.isEmpty()) continue
            var matchedInHostname = false
            for (index in labels.indices) {
                val alias = entryVariants.firstOrNull { it in labelTokenSets[index] } ?: continue
                val confusable = labelConfusable[index]
                val isRegistrable = labelIsRegistrable[index]
                val base = if (isRegistrable) SCORE_REGISTRABLE else SCORE_SUBDOMAIN
                val score = minOf(1.0, base + if (confusable) CONFUSABLE_BONUS else 0.0)
                matches.add(BrandMatch(entry.brandId, alias, if (isRegistrable) LOCATION_REGISTRABLE else LOCATION_SUBDOMAIN, confusable))
                riskScore = maxOf(riskScore, score)
                hostnameMatch = true
                matchedInHostname = true
                break
            }
            if (!matchedInHostname) {
                val alias = entryVariants.firstOrNull { it in textTokens }
                if (alias != null) {
                    matches.add(BrandMatch(entry.brandId, alias, LOCATION_PATH, false))
                    riskScore = maxOf(riskScore, SCORE_PATH)
                }
            }
        }
        return BrandAssessment(
            detected = matches.isNotEmpty(),
            officialDomain = false,
            domainMismatch = hostnameMatch,
            riskScore = riskScore,
            brands = matches,
        )
    }

    companion object {
        const val LOCATION_REGISTRABLE = "registrable_domain"
        const val LOCATION_SUBDOMAIN = "subdomain"
        const val LOCATION_PATH = "path"
        private const val SCORE_REGISTRABLE = 0.85
        private const val SCORE_SUBDOMAIN = 0.70
        private const val SCORE_PATH = 0.35
        private const val CONFUSABLE_BONUS = 0.10
    }
}
