import json
from pathlib import Path

import pytest

from scripts.build_adversarial_corpus import build_corpus
from src.data.normalizer import URLNormalizationError, normalize_url
from src.intel.brand_engine import BrandDetectionEngine
from src.intel.shortener_engine import ShortenerDetectionEngine
from src.security.schemes import SchemeOutcome, classify_scheme

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "deployment" / "security" / "adversarial_urls_v1.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in CORPUS["urlCases"]}


def test_corpus_is_locked_to_the_reference_implementation() -> None:
    rebuilt = build_corpus()
    assert rebuilt == CORPUS, "corpus drifted from the reference implementation; rerun scripts/build_adversarial_corpus.py"


def test_corpus_shape() -> None:
    assert CORPUS["corpusVersion"] == "adversarial-url-corpus-v1"
    assert CORPUS["urlCaseCount"] >= 40
    assert CORPUS["brandCaseCount"] >= 10
    assert CORPUS["shortenerCaseCount"] >= 8
    assert CORPUS["unsupportedSchemeCount"] >= 7


def test_unsupported_schemes_are_never_accepted() -> None:
    checked = 0
    for case in CORPUS["urlCases"]:
        if case["schemeOutcome"] != SchemeOutcome.UNSUPPORTED_SCHEME.value:
            continue
        checked += 1
        assert case["outcome"] == "UNSUPPORTED_SCHEME"
        assert case["detail"] == "Only HTTP and HTTPS URLs are accepted"
        with pytest.raises(URLNormalizationError, match="Only HTTP and HTTPS"):
            normalize_url(case["input"])
    assert checked >= 7


def test_scheme_outcome_and_normalizer_outcome_are_consistent() -> None:
    for case in CORPUS["urlCases"]:
        outcome, _ = classify_scheme(case["input"])
        assert outcome.value == case["schemeOutcome"]
        if outcome is SchemeOutcome.MALFORMED:
            assert case["outcome"] == "MALFORMED"
        if outcome in {SchemeOutcome.HTTP, SchemeOutcome.HTTPS, SchemeOutcome.IMPLIED_HTTPS}:
            assert case["outcome"] in {"ACCEPTED", "MALFORMED"}


def test_key_parser_ambiguity_outcomes() -> None:
    assert CASES["trailing_dot"]["normalizedUrl"] == "https://example.com/"
    assert CASES["mixed_case"]["normalizedUrl"] == "https://example.com/MiXeD"
    assert CASES["default_port"]["normalizedUrl"] == "http://example.com/"
    assert CASES["non_default_port"]["normalizedUrl"] == "https://example.com:8443/"
    assert CASES["attacker_official_subdomain_trick"]["registrableDomain"] == "paypal.com.attacker.example"
    assert CASES["ipv6_host"]["hostname"] == "2001:db8::1"
    assert CASES["userinfo_at_syntax"]["normalizedUrl"] == "https://user:secret@example.com/path"
    assert CASES["crlf_percent_encoded"]["normalizedUrl"] == "https://example.com/%0D%0ASet-Cookie:x"
    assert CASES["overlong_label"]["outcome"] == "MALFORMED"
    assert CASES["invalid_port"]["outcome"] == "MALFORMED"
    assert CASES["scheme_relative"]["outcome"] == "MALFORMED"


def test_brand_hostname_identity_only() -> None:
    engine = BrandDetectionEngine()
    hostname_identity = engine.assess(normalize_url("https://google.com.attacker.example/"))
    assert hostname_identity.domain_mismatch
    official = engine.assess(normalize_url("https://accounts.google.com/"))
    assert official.official_domain and not official.domain_mismatch
    path_only = engine.assess(normalize_url("https://example.com/paypal"))
    assert path_only.detected and not path_only.domain_mismatch
    fragment_only = engine.assess(normalize_url("https://example.com/page#paypal"))
    assert not fragment_only.detected


def test_brand_adversarial_expectations() -> None:
    engine = BrandDetectionEngine()
    expectations = {
        "https://google.com.attacker.example/": (True, False, True),
        "https://accounts.google.com/": (True, True, False),
        "https://google-login.example/": (True, False, True),
        "https://google.example.com/": (True, False, True),
        "https://apple.com.attacker.example/": (True, False, True),
        "https://paypa1.example/": (True, False, True),
        "https://micros0ft.example/": (True, False, True),
        "https://paypal.com.evil.com/": (True, False, True),
        "https://example.com/paypal": (True, False, False),
        "https://example.com/page#paypal": (False, False, False),
    }
    for raw, (detected, official, mismatch) in expectations.items():
        assessment = engine.assess(normalize_url(raw))
        assert (assessment.detected, assessment.official_domain, assessment.domain_mismatch) == (
            detected, official, mismatch,
        ), raw
    assert engine.assess(normalize_url("https://paypa1.example/")).risk_score >= 0.85


def test_shortener_adversarial_expectations() -> None:
    engine = ShortenerDetectionEngine()
    assert engine.assess(normalize_url("https://bit.ly/abc")).domain == "bit.ly"
    assert engine.assess(normalize_url("https://go.bit.ly/xyz")).detected
    assert engine.assess(normalize_url("https://sub.t.co/xyz")).domain == "t.co"
    assert not engine.assess(normalize_url("https://fake-shortener.example/")).detected
    assert not engine.assess(normalize_url("https://bit.ly.attacker.example/abc")).detected
    assert not engine.assess(normalize_url("https://bit-ly.example/abc")).detected
    assert not engine.assess(normalize_url("https://example.com/bit.ly/abc")).detected
    assert not engine.assess(normalize_url("https://youtu.be/abc")).detected


def test_brand_case_parity_corpus_matches_engine() -> None:
    engine = BrandDetectionEngine()
    for case in CORPUS["brandCases"]:
        assessment = engine.assess(normalize_url(case["input"]))
        assert assessment.detected == case["expectedDetected"], case["input"]
        assert assessment.official_domain == case["expectedOfficialDomain"], case["input"]
        assert assessment.domain_mismatch == case["expectedDomainMismatch"], case["input"]
        assert assessment.risk_score == case["expectedRiskScore"], case["input"]
        assert sorted(
            [{"brandId": match.brand_id, "location": match.location, "confusable": match.confusable}
             for match in assessment.brands],
            key=lambda item: (item["brandId"], item["location"]),
        ) == case["expectedBrands"], case["input"]
