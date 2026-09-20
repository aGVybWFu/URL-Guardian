from src.data.normalizer import normalize_url
from src.intel.brand_engine import BrandDetectionEngine
from src.intel.confusables import label_tokens, skeleton, skeleton_variants

ENGINE = BrandDetectionEngine()


def assess(raw: str):
    return ENGINE.assess(normalize_url(raw))


def test_official_brand_domain_is_protected() -> None:
    for raw in ("https://www.paypal.com/login", "https://login.paypal.com/session", "https://paypal.com/"):
        result = assess(raw)
        assert result.detected
        assert result.official_domain
        assert not result.domain_mismatch
        assert result.risk_score == 0.0


def test_official_brand_domain_without_alias_token() -> None:
    result = assess("https://fb.com/")
    assert result.detected
    assert result.official_domain
    assert result.risk_score == 0.0


def test_registrable_domain_brand_mismatch() -> None:
    result = assess("https://paypal-login.com/")
    assert result.detected
    assert result.domain_mismatch
    assert not result.official_domain
    assert result.risk_score >= 0.85
    assert result.to_features()["brand_domain_mismatch"] == 1.0


def test_subdomain_brand_mismatch() -> None:
    result = assess("https://paypal.com.evil.com/")
    assert result.domain_mismatch
    assert 0.6 <= result.risk_score < 0.85


def test_confusable_digit_substitution_raises_score() -> None:
    plain = assess("https://paypal-login.com/")
    confusable = assess("https://paypa1-login.com/")
    assert confusable.domain_mismatch
    assert confusable.risk_score > plain.risk_score
    assert any(match.confusable for match in confusable.brands)


def test_idn_punycode_brand_match() -> None:
    host = "раypal.com".encode("idna").decode("ascii")
    result = assess(f"https://{host}/")
    assert result.detected
    assert result.domain_mismatch
    assert any(match.confusable for match in result.brands)
    assert result.risk_score >= 0.85


def test_path_only_mention_is_weak_and_not_a_mismatch() -> None:
    result = assess("https://example.com/paypal/login")
    assert result.detected
    assert not result.domain_mismatch
    assert result.risk_score <= 0.5


def test_token_boundary_avoids_substring_false_positive() -> None:
    result = assess("https://applepie.example.com/")
    assert not result.detected
    assert result.risk_score == 0.0


def test_unrelated_domain_is_clean() -> None:
    result = assess("https://example.com/")
    assert not result.detected
    assert not result.domain_mismatch
    assert result.risk_score == 0.0


def test_skeleton_helpers_are_deterministic() -> None:
    assert skeleton("РАYPAL") == "paypal"
    assert skeleton_variants("rnicrosoft") == {"microsoft", "rnicrosoft"}
    assert label_tokens("paypal-secure") == {"paypal", "secure"}
    assert label_tokens("applepie") == {"applepie"}
