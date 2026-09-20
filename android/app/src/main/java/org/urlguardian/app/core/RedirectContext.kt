package org.urlguardian.app.core

const val REDIRECT_NOT_OBSERVED = "NOT_OBSERVED"
const val REDIRECT_OBSERVED = "OBSERVED"

data class RedirectContext(
    val status: String,
    val redirectCount: Int = 0,
    val crossDomainRedirect: Boolean = false,
    val finalHostname: String? = null,
    val error: String? = null,
) {
    init {
        require(status == REDIRECT_NOT_OBSERVED || status == REDIRECT_OBSERVED) { "unknown redirect status" }
        require(redirectCount >= 0) { "redirectCount must not be negative" }
    }

    val observed: Boolean get() = status == REDIRECT_OBSERVED

    fun toFeatures(): Map<String, Double> {
        if (!observed) return emptyMap()
        return mapOf(
            "redirect_count" to redirectCount.toDouble(),
            "cross_domain_redirect" to if (crossDomainRedirect) 1.0 else 0.0,
        )
    }

    fun availability(): Map<String, Boolean> = mapOf(
        "redirect_count" to observed,
        "cross_domain_redirect" to observed,
    )

    companion object {
        fun notObserved() = RedirectContext(REDIRECT_NOT_OBSERVED)
    }
}

interface RedirectResolver {
    fun resolve(url: NormalizedUrl): RedirectContext
}

class NoOpRedirectResolver : RedirectResolver {
    override fun resolve(url: NormalizedUrl): RedirectContext = RedirectContext.notObserved()
}

class FixtureRedirectResolver(private val contexts: Map<String, RedirectContext>) : RedirectResolver {
    override fun resolve(url: NormalizedUrl): RedirectContext = contexts[url.normalizedUrl] ?: RedirectContext.notObserved()
}
