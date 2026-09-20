from src.policy.v2 import (
    BRAND_SCORE_REVIEW_AT,
    POLICY_VERSION_V2,
    ReasonCode,
    V2_THRESHOLDS,
    decide_v2,
)
from src.ugdm.policy import POLICY_VERSION as POLICY_VERSION_V1


def availability(**overrides: bool) -> dict[str, bool]:
    base = {
        "known_malicious": False,
        "whitelist_hit": False,
        "brand_detected": False,
        "brand_domain_mismatch": False,
        "brand_risk_score": False,
        "shortener_detected": False,
        "cross_domain_redirect": False,
        "redirect_count": False,
    }
    base.update(overrides)
    return base


def test_v1_is_untouched() -> None:
    assert POLICY_VERSION_V1 == "DecisionPolicyV1"
    assert POLICY_VERSION_V2 == "DecisionPolicyV2"
    assert V2_THRESHOLDS.review_at == 0.35
    assert V2_THRESHOLDS.block_at == 0.85


def test_guardrail_overrides_official_brand_domain() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.01, "known_malicious": 1.0, "brand_detected": 1.0},
        availability(known_malicious=True, brand_detected=True, brand_risk_score=True),
    )
    assert decision.action == "BLOCK"
    assert decision.reason_code is ReasonCode.KNOWN_MALICIOUS_GUARDRAIL


def test_official_brand_domain_allows_at_low_probability() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.10, "brand_detected": 1.0, "brand_risk_score": 0.0},
        availability(brand_detected=True, brand_risk_score=True),
    )
    assert decision.action == "ALLOW"
    assert decision.reason_code is ReasonCode.OFFICIAL_BRAND_DOMAIN_ALLOW


def test_official_brand_domain_allows_even_at_high_probability() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.60, "brand_detected": 1.0, "brand_risk_score": 0.0},
        availability(brand_detected=True, brand_risk_score=True),
    )
    assert decision.action == "ALLOW"
    assert decision.reason_code is ReasonCode.OFFICIAL_BRAND_DOMAIN_ALLOW


def test_official_brand_domain_with_observed_redirect_reviews() -> None:
    decision = decide_v2(
        {
            "phishing_probability": 0.10,
            "brand_detected": 1.0,
            "brand_risk_score": 0.0,
            "cross_domain_redirect": 1.0,
            "redirect_count": 2.0,
        },
        availability(brand_detected=True, brand_risk_score=True, cross_domain_redirect=True, redirect_count=True),
    )
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.CROSS_DOMAIN_REDIRECT_REVIEW


def test_brand_mismatch_blocks_at_block_threshold() -> None:
    decision = decide_v2(
        {
            "phishing_probability": 0.90,
            "brand_detected": 1.0,
            "brand_domain_mismatch": 1.0,
            "brand_risk_score": 0.95,
        },
        availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True),
    )
    assert decision.action == "BLOCK"
    assert decision.reason_code is ReasonCode.BRAND_IMPERSONATION_BLOCK


def test_brand_mismatch_reviews_between_thresholds() -> None:
    decision = decide_v2(
        {
            "phishing_probability": 0.50,
            "brand_detected": 1.0,
            "brand_domain_mismatch": 1.0,
            "brand_risk_score": 0.85,
        },
        availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True),
    )
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.BRAND_IMPERSONATION_REVIEW


def test_high_brand_score_reviews_even_at_low_probability() -> None:
    decision = decide_v2(
        {
            "phishing_probability": 0.05,
            "brand_detected": 1.0,
            "brand_domain_mismatch": 1.0,
            "brand_risk_score": BRAND_SCORE_REVIEW_AT,
        },
        availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True),
    )
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.BRAND_IMPERSONATION_REVIEW


def test_shortener_alone_reviews_and_never_blocks() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.05, "shortener_detected": 1.0},
        availability(shortener_detected=True),
    )
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.SHORTENER_REVIEW


def test_shortener_with_independent_evidence_can_block() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.95, "shortener_detected": 1.0, "contains_login": 1.0},
        availability(shortener_detected=True, contains_login=True),
    )
    assert decision.action == "BLOCK"
    assert decision.reason_code is ReasonCode.HIGH_PROBABILITY_WITH_EVIDENCE


def test_observed_cross_domain_redirect_reviews() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.05, "cross_domain_redirect": 1.0, "redirect_count": 3.0},
        availability(cross_domain_redirect=True, redirect_count=True),
    )
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.CROSS_DOMAIN_REDIRECT_REVIEW


def test_unobserved_redirect_is_unavailable_not_safe() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.05, "cross_domain_redirect": 0.0},
        availability(),
    )
    assert decision.action == "ALLOW"
    assert decision.reason_code is ReasonCode.LOW_RISK


def test_whitelist_allows_without_overriding_guardrail() -> None:
    allowed = decide_v2(
        {"phishing_probability": 0.05, "whitelist_hit": 1.0},
        availability(whitelist_hit=True),
    )
    assert allowed.action == "ALLOW"
    assert allowed.reason_code is ReasonCode.WHITELIST_ALLOW
    blocked = decide_v2(
        {"phishing_probability": 0.05, "whitelist_hit": 1.0, "known_malicious": 1.0},
        availability(whitelist_hit=True, known_malicious=True),
    )
    assert blocked.action == "BLOCK"


def test_high_probability_with_evidence_blocks() -> None:
    decision = decide_v2(
        {"phishing_probability": 0.90, "contains_login": 1.0},
        availability(contains_login=True),
    )
    assert decision.action == "BLOCK"
    assert decision.reason_code is ReasonCode.HIGH_PROBABILITY_WITH_EVIDENCE


def test_high_probability_without_evidence_reviews() -> None:
    decision = decide_v2({"phishing_probability": 0.90}, availability())
    assert decision.action == "REVIEW"
    assert decision.reason_code is ReasonCode.ELEVATED_PROBABILITY


def test_low_probability_no_evidence_allows() -> None:
    decision = decide_v2({"phishing_probability": 0.10}, availability())
    assert decision.action == "ALLOW"
    assert decision.reason_code is ReasonCode.LOW_RISK


def test_decision_serialisation_is_stable() -> None:
    decision = decide_v2({"phishing_probability": 0.10}, availability())
    payload = decision.to_dict()
    assert payload["policyVersion"] == "DecisionPolicyV2"
    assert payload["reasonCode"] == "LOW_RISK"
    assert payload["targetProvenance"] == "POLICY_SUPERVISED"
