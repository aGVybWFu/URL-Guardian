package org.urlguardian.app.core

import java.util.Locale

data class ShortenerAssessment(val detected: Boolean, val domain: String?) {
    fun toFeatures(): Map<String, Double> = mapOf("shortener_detected" to if (detected) 1.0 else 0.0)

    fun availability(): Map<String, Boolean> = mapOf("shortener_detected" to true)

    companion object {
        val NONE = ShortenerAssessment(false, null)
    }
}

class ShortenerDetectionEngine(catalog: ShortenerCatalog) {
    private val domains = catalog.domains.map { it.lowercase(Locale.ROOT) }.toSortedSet()
    val catalogSize: Int = catalog.domains.size

    fun assess(url: NormalizedUrl): ShortenerAssessment {
        val hostname = url.hostname.lowercase(Locale.ROOT)
        val registrable = url.registrableDomain.lowercase(Locale.ROOT)
        for (domain in domains) {
            if (registrable == domain || hostname == domain || hostname.endsWith(".$domain")) {
                return ShortenerAssessment(true, domain)
            }
        }
        return ShortenerAssessment.NONE
    }
}
