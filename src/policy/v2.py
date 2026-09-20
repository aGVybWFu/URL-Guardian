"""DecisionPolicyV2: DecisionPolicyV1 rules plus brand, shortener and redirect signals.

V1 is not modified. V2 keeps the same probability thresholds and the same
confirmed-malicious guardrail, and adds documented rules for the Phase 5
signals:

* An official brand domain is an explicit allow signal at low probability.
* A brand token on a non-official registrable domain is impersonation evidence;
  it can block at the block threshold and reviews at the review threshold or at
  a high brand risk score.
* A shortener is an opacity signal: it reviews and can never block on its own.
* An observed cross-domain redirect reviews. Redirect evidence is only used when
  a resolver actually observed the chain; `NOT_OBSERVED` is unavailable, not safe.

Every decision carries a stable `ReasonCode`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from src.ugdm.policy import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_REVIEW,
    RISK_DANGEROUS,
    RISK_SAFE,
    RISK_SUSPICIOUS,
    PolicyThresholds,
    TARGET_PROVENANCE,
    risk_evidence_count,
)

POLICY_VERSION_V2 = "DecisionPolicyV2"
V2_THRESHOLDS = PolicyThresholds(review_at=0.35, block_at=0.85)
BRAND_SCORE_REVIEW_AT = 0.5
REASON_CODE_VERSION = "ReasonCodeV1"


class ReasonCode(str, Enum):
    KNOWN_MALICIOUS_GUARDRAIL = "KNOWN_MALICIOUS_GUARDRAIL"
    WHITELIST_ALLOW = "WHITELIST_ALLOW"
    OFFICIAL_BRAND_DOMAIN_ALLOW = "OFFICIAL_BRAND_DOMAIN_ALLOW"
    LOW_RISK = "LOW_RISK"
    BRAND_IMPERSONATION_BLOCK = "BRAND_IMPERSONATION_BLOCK"
    BRAND_IMPERSONATION_REVIEW = "BRAND_IMPERSONATION_REVIEW"
    HIGH_PROBABILITY_WITH_EVIDENCE = "HIGH_PROBABILITY_WITH_EVIDENCE"
    SHORTENER_REVIEW = "SHORTENER_REVIEW"
    CROSS_DOMAIN_REDIRECT_REVIEW = "CROSS_DOMAIN_REDIRECT_REVIEW"
    ELEVATED_PROBABILITY = "ELEVATED_PROBABILITY"


@dataclass(frozen=True)
class DecisionV2:
    risk: str
    action: str
    reason_code: ReasonCode
    phishing_probability: float
    risk_evidence_count: int
    known_malicious: bool
    whitelisted: bool
    brand_mismatch: bool
    shortener_detected: bool
    cross_domain_redirect: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "action": self.action,
            "reasonCode": self.reason_code.value,
            "phishingProbability": self.phishing_probability,
            "riskEvidenceCount": self.risk_evidence_count,
            "knownMalicious": self.known_malicious,
            "whitelisted": self.whitelisted,
            "brandMismatch": self.brand_mismatch,
            "shortenerDetected": self.shortener_detected,
            "crossDomainRedirect": self.cross_domain_redirect,
            "policyVersion": POLICY_VERSION_V2,
            "targetProvenance": TARGET_PROVENANCE,
        }


def _available(availability: Mapping[str, bool], name: str) -> bool:
    return bool(availability.get(name, False))


def _flag(features: Mapping[str, float], availability: Mapping[str, bool], name: str) -> bool:
    return _available(availability, name) and float(features.get(name, 0.0)) >= 0.5


def decide_v2(
    features: Mapping[str, float],
    availability: Mapping[str, bool],
    thresholds: PolicyThresholds = V2_THRESHOLDS,
) -> DecisionV2:
    phishing_probability = float(features.get("phishing_probability", 0.0))
    known_malicious = _flag(features, availability, "known_malicious")
    whitelisted = _flag(features, availability, "whitelist_hit")
    brand_detected = _flag(features, availability, "brand_detected")
    brand_mismatch = _flag(features, availability, "brand_domain_mismatch")
    brand_score = float(features.get("brand_risk_score", 0.0)) if _available(availability, "brand_risk_score") else 0.0
    shortener_detected = _flag(features, availability, "shortener_detected")
    cross_domain_redirect = _flag(features, availability, "cross_domain_redirect")
    official_brand_domain = brand_detected and not brand_mismatch and brand_score <= 0.0
    evidence = risk_evidence_count(features, availability)

    def decision(risk: str, action: str, code: ReasonCode) -> DecisionV2:
        return DecisionV2(
            risk=risk,
            action=action,
            reason_code=code,
            phishing_probability=phishing_probability,
            risk_evidence_count=evidence,
            known_malicious=known_malicious,
            whitelisted=whitelisted,
            brand_mismatch=brand_mismatch,
            shortener_detected=shortener_detected,
            cross_domain_redirect=cross_domain_redirect,
        )

    # 1. Confirmed intelligence evidence always wins, even over an official brand domain.
    if known_malicious:
        return decision(RISK_DANGEROUS, ACTION_BLOCK, ReasonCode.KNOWN_MALICIOUS_GUARDRAIL)
    # 2. Local whitelist.
    if whitelisted:
        return decision(RISK_SAFE, ACTION_ALLOW, ReasonCode.WHITELIST_ALLOW)
    # 3. The brand's own canonical domain is an explicit allow: the identity is
    #    catalog-verified, and the guardrail above still catches confirmed
    #    malicious evidence. An observed cross-domain redirect falls through.
    if official_brand_domain and not cross_domain_redirect:
        return decision(RISK_SAFE, ACTION_ALLOW, ReasonCode.OFFICIAL_BRAND_DOMAIN_ALLOW)
    # 4. Brand impersonation.
    if brand_mismatch:
        if phishing_probability >= thresholds.block_at:
            return decision(RISK_DANGEROUS, ACTION_BLOCK, ReasonCode.BRAND_IMPERSONATION_BLOCK)
        if phishing_probability >= thresholds.review_at or brand_score >= BRAND_SCORE_REVIEW_AT:
            return decision(RISK_SUSPICIOUS, ACTION_REVIEW, ReasonCode.BRAND_IMPERSONATION_REVIEW)
    # 5. High probability with at least one supporting signal.
    if phishing_probability >= thresholds.block_at and evidence >= 1:
        return decision(RISK_DANGEROUS, ACTION_BLOCK, ReasonCode.HIGH_PROBABILITY_WITH_EVIDENCE)
    # 6. A shortener is opaque: review, never a block on its own.
    if shortener_detected:
        return decision(RISK_SUSPICIOUS, ACTION_REVIEW, ReasonCode.SHORTENER_REVIEW)
    # 7. An observed cross-domain redirect reviews.
    if cross_domain_redirect:
        return decision(RISK_SUSPICIOUS, ACTION_REVIEW, ReasonCode.CROSS_DOMAIN_REDIRECT_REVIEW)
    # 8. Elevated probability.
    if phishing_probability >= thresholds.review_at or (
        phishing_probability >= thresholds.block_at and evidence == 0
    ):
        return decision(RISK_SUSPICIOUS, ACTION_REVIEW, ReasonCode.ELEVATED_PROBABILITY)
    # 9. No meaningful evidence of risk.
    return decision(RISK_SAFE, ACTION_ALLOW, ReasonCode.LOW_RISK)
