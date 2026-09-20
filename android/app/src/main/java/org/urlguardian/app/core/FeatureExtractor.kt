package org.urlguardian.app.core

import kotlin.math.ln

data class ExtractedFeatures(val values: Map<String, Double>, val availability: Map<String, Boolean>)

object FeatureExtractor {
    private val keywords = listOf("login", "signin", "verify", "verification", "secure", "account", "password", "update", "payment", "wallet", "bank", "confirm", "auth", "oauth")

    val alwaysAvailable: Set<String> = buildSet {
        addAll(listOf(
            "url_length", "hostname_length", "subdomain_count", "digit_ratio", "special_character_ratio",
            "hostname_entropy", "has_ip", "has_punycode", "has_at_symbol", "uses_https", "has_non_default_port",
        ))
        keywords.forEach { add("contains_$it") }
    }

    fun extract(url: NormalizedUrl): Map<String, Double> {
        val text = url.normalizedUrl
        val lower = text.lowercase()
        val digits = text.count { it.isDigit() }
        val specials = text.count { !it.isLetterOrDigit() }
        val hasIp = url.hostname.contains(':') || url.hostname.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))
        val nonDefaultPort = url.port != null && !((url.scheme == "http" && url.port == 80) || (url.scheme == "https" && url.port == 443))
        val values = mutableMapOf(
            "url_length" to text.length.toDouble(),
            "hostname_length" to url.hostname.length.toDouble(),
            "subdomain_count" to url.subdomain.split('.').count { it.isNotEmpty() }.toDouble(),
            "digit_ratio" to digits.toDouble() / text.length,
            "special_character_ratio" to specials.toDouble() / text.length,
            "hostname_entropy" to entropy(url.hostname),
            "has_ip" to if (hasIp) 1.0 else 0.0,
            "has_punycode" to if (url.hostname.split('.').any { it.startsWith("xn--") }) 1.0 else 0.0,
            "has_at_symbol" to if ('@' in text) 1.0 else 0.0,
            "uses_https" to if (url.scheme == "https") 1.0 else 0.0,
            "has_non_default_port" to if (nonDefaultPort) 1.0 else 0.0,
        )
        keywords.forEach { values["contains_$it"] = if (it in lower) 1.0 else 0.0 }
        return values
    }

    fun extractV2(
        url: NormalizedUrl,
        brand: BrandAssessment,
        shortener: ShortenerAssessment,
        redirect: RedirectContext,
        threatIntelAvailable: Boolean,
        knownMalicious: Boolean,
        brandCatalogAvailable: Boolean,
        shortenerCatalogAvailable: Boolean,
    ): ExtractedFeatures {
        val values = extract(url).toMutableMap()
        values.putAll(brand.toFeatures())
        values.putAll(shortener.toFeatures())
        values.putAll(redirect.toFeatures())
        values["known_malicious"] = if (knownMalicious) 1.0 else 0.0
        val availability = mutableMapOf<String, Boolean>()
        alwaysAvailable.forEach { availability[it] = true }
        availability["known_malicious"] = threatIntelAvailable
        brand.availability().forEach { (name, available) -> availability[name] = available && brandCatalogAvailable }
        shortener.availability().forEach { (name, available) -> availability[name] = available && shortenerCatalogAvailable }
        redirect.availability().forEach { (name, available) -> availability[name] = available }
        availability["blacklist_hit"] = false
        availability["whitelist_hit"] = false
        return ExtractedFeatures(values, availability)
    }

    private fun entropy(value: String): Double {
        if (value.isEmpty()) return 0.0
        return value.groupingBy { it }.eachCount().values.sumOf { count ->
            val p = count.toDouble() / value.length
            -p * (ln(p) / ln(2.0))
        }
    }
}
