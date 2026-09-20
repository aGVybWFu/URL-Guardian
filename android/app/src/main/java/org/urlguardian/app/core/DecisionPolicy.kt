package org.urlguardian.app.core

enum class Risk { SAFE, SUSPICIOUS, DANGEROUS }
enum class Action { ALLOW, REVIEW, BLOCK }
enum class ThreatIntelStatus { KNOWN_MALICIOUS, UNKNOWN, UNAVAILABLE, ERROR }

data class PolicyDecision(val risk: Risk, val action: Action, val reason: String, val evidenceCount: Int)

object DecisionPolicyV1 {
    const val VERSION = "DecisionPolicyV1"
    const val REVIEW_AT = 0.35f
    const val BLOCK_AT = 0.85f
    private val evidenceNames = listOf(
        "has_ip", "has_punycode", "has_at_symbol", "has_non_default_port", "contains_login",
        "contains_verify", "contains_secure", "contains_account", "contains_password",
        "contains_payment", "contains_wallet", "brand_domain_mismatch",
    )

    fun decide(phishingProbability: Float, features: Map<String, Double>, threatIntel: ThreatIntelStatus): PolicyDecision {
        val evidence = evidenceNames.count { (features[it] ?: 0.0) >= 0.5 }
        if (threatIntel == ThreatIntelStatus.KNOWN_MALICIOUS) {
            return PolicyDecision(Risk.DANGEROUS, Action.BLOCK, "threat_intelligence_known_malicious", evidence)
        }
        if (phishingProbability >= BLOCK_AT && evidence >= 1) {
            return PolicyDecision(Risk.DANGEROUS, Action.BLOCK, "high_phishing_probability_with_supporting_evidence", evidence)
        }
        if (phishingProbability >= REVIEW_AT) {
            return PolicyDecision(Risk.SUSPICIOUS, Action.REVIEW, "elevated_phishing_probability", evidence)
        }
        return PolicyDecision(Risk.SAFE, Action.ALLOW, "low_probability_no_risk_evidence", evidence)
    }
}
