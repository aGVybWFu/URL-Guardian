package org.urlguardian.app.core

data class EngineDecision(
    val risk: Risk,
    val action: Action,
    val reasonCode: ReasonCode,
    val reason: String,
    val evidenceCount: Int,
    val engineVersion: String,
)

object DecisionPolicyV2 {
    const val VERSION = "DecisionPolicyV2"
    const val REVIEW_AT = 0.35f
    const val BLOCK_AT = 0.85f
    const val BRAND_SCORE_REVIEW_AT = 0.5
    // Deliberately duplicated from DecisionPolicyV1 so the frozen V1 source stays
    // untouched. The two lists must stay identical; parity tests cover them.
    private val evidenceNames = listOf(
        "has_ip", "has_punycode", "has_at_symbol", "has_non_default_port", "contains_login",
        "contains_verify", "contains_secure", "contains_account", "contains_password",
        "contains_payment", "contains_wallet", "brand_domain_mismatch",
    )

    fun decide(
        phishingProbability: Float,
        features: Map<String, Double>,
        availability: Map<String, Boolean>,
        threatIntel: ThreatIntelStatus,
    ): EngineDecision {
        fun flag(name: String): Boolean = (availability[name] ?: false) && (features[name] ?: 0.0) >= 0.5

        val evidence = evidenceNames.count { flag(it) }
        val knownMalicious = threatIntel == ThreatIntelStatus.KNOWN_MALICIOUS || flag("known_malicious")
        val whitelisted = flag("whitelist_hit")
        val brandDetected = flag("brand_detected")
        val brandMismatch = flag("brand_domain_mismatch")
        val brandScore = if (availability["brand_risk_score"] ?: false) features["brand_risk_score"] ?: 0.0 else 0.0
        val shortenerDetected = flag("shortener_detected")
        val crossDomainRedirect = flag("cross_domain_redirect")
        val officialBrandDomain = brandDetected && !brandMismatch && brandScore <= 0.0

        fun decision(risk: Risk, action: Action, code: ReasonCode) =
            EngineDecision(risk, action, code, code.code, evidence, VERSION)

        if (knownMalicious) return decision(Risk.DANGEROUS, Action.BLOCK, ReasonCode.KNOWN_MALICIOUS_GUARDRAIL)
        if (whitelisted) return decision(Risk.SAFE, Action.ALLOW, ReasonCode.WHITELIST_ALLOW)
        if (officialBrandDomain && !crossDomainRedirect) {
            return decision(Risk.SAFE, Action.ALLOW, ReasonCode.OFFICIAL_BRAND_DOMAIN_ALLOW)
        }
        if (brandMismatch) {
            if (phishingProbability >= BLOCK_AT) {
                return decision(Risk.DANGEROUS, Action.BLOCK, ReasonCode.BRAND_IMPERSONATION_BLOCK)
            }
            if (phishingProbability >= REVIEW_AT || brandScore >= BRAND_SCORE_REVIEW_AT) {
                return decision(Risk.SUSPICIOUS, Action.REVIEW, ReasonCode.BRAND_IMPERSONATION_REVIEW)
            }
        }
        if (phishingProbability >= BLOCK_AT && evidence >= 1) {
            return decision(Risk.DANGEROUS, Action.BLOCK, ReasonCode.HIGH_PROBABILITY_WITH_EVIDENCE)
        }
        if (shortenerDetected) return decision(Risk.SUSPICIOUS, Action.REVIEW, ReasonCode.SHORTENER_REVIEW)
        if (crossDomainRedirect) return decision(Risk.SUSPICIOUS, Action.REVIEW, ReasonCode.CROSS_DOMAIN_REDIRECT_REVIEW)
        if (phishingProbability >= REVIEW_AT || (phishingProbability >= BLOCK_AT && evidence == 0)) {
            return decision(Risk.SUSPICIOUS, Action.REVIEW, ReasonCode.ELEVATED_PROBABILITY)
        }
        return decision(Risk.SAFE, Action.ALLOW, ReasonCode.LOW_RISK)
    }
}
