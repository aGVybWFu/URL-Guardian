"""Build the Phase 6 Adversarial URL Security Corpus v1.

Every fixture is a synthetic reserved-domain string. Nothing is requested,
resolved or opened. Expected values are computed from the Python reference
implementation that the Android side mirrors, so the corpus doubles as a
cross-language parity lock.

The corpus never claims a URL is safe or malicious; it locks parser, scheme,
brand and shortener behaviour against regressions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from src.data.normalizer import URLNormalizationError, normalize_url
from src.intel.brand_engine import BrandDetectionEngine
from src.intel.shortener_engine import ShortenerDetectionEngine
from src.security.schemes import SchemeOutcome, classify_scheme

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "deployment" / "security" / "adversarial_urls_v1.json"
CORPUS_VERSION = "adversarial-url-corpus-v1"
GENERATED_AT = "2026-09-20"

IDN_BRAND_HOST = "раypal.com".encode("idna").decode("ascii")
GREEK_BRAND_HOST = "gοοgle.com".encode("idna").decode("ascii")

URL_CASES: tuple[tuple[str, str, str], ...] = (
    ("nested_subdomains", "structure", "https://a.b.c.d.example.com/path?x=1"),
    ("brand_token_path_only", "brand", "https://example.com/paypal/login"),
    ("brand_token_query_only", "brand", "https://example.com/?next=paypal"),
    ("brand_token_fragment_only", "brand", "https://example.com/page#paypal"),
    ("official_domain_deceptive_path", "brand", "https://www.paypal.com/verify-account/login"),
    ("attacker_official_subdomain_trick", "brand", "https://paypal.com.attacker.example/login"),
    ("punycode_host", "encoding", f"https://{IDN_BRAND_HOST}/"),
    ("idn_unicode_host", "encoding", "https://раypal.com/"),
    ("unicode_homoglyph_host", "encoding", "https://gοοgle.com/"),
    ("punycode_greek_homoglyph", "encoding", f"https://{GREEK_BRAND_HOST}/"),
    ("very_long_hostname", "structure", "https://" + "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".example/"),
    ("maximum_label_length", "structure", "https://" + "a" * 63 + ".example.com/"),
    ("overlong_label", "structure", "https://" + "a" * 64 + ".example.com/"),
    ("multiple_hyphens", "structure", "https://a--b---c.example.com/"),
    ("digit_substitution_host", "encoding", "https://paypa1.example.com/"),
    ("userinfo_at_syntax", "structure", "https://user:secret@example.com/path"),
    ("ipv4_host", "host", "http://192.0.2.10/test"),
    ("ipv6_host", "host", "https://[2001:db8::1]:8443/demo"),
    ("encoded_characters", "encoding", "https://example.com/%2Fpath%3Fq%3D1"),
    ("double_encoding", "encoding", "https://example.com/%252Fadmin"),
    ("mixed_case", "normalization", "HTTPS://EXAMPLE.COM/MiXeD"),
    ("trailing_dot", "normalization", "https://example.com./"),
    ("default_port", "port", "http://example.com:80/"),
    ("non_default_port", "port", "https://example.com:8443/"),
    ("invalid_port", "port", "https://example.com:99999/"),
    ("shortener_domain", "shortener", "https://bit.ly/abc123"),
    ("shortener_lookalike", "shortener", "https://bit.ly.example.com/abc"),
    ("shortener_token_in_path", "shortener", "https://example.com/bit.ly/abc"),
    ("localhost_like", "host", "https://localhost.example/"),
    ("single_label_host", "host", "https://localhost/"),
    ("malformed_empty", "malformed", ""),
    ("malformed_missing_host", "malformed", "https:///path"),
    ("malformed_space_in_host", "malformed", "https://exa mple.com/"),
    ("malformed_bad_percent", "malformed", "https://example.com/%zz"),
    ("malformed_control_char", "malformed", "https://example.com/\u0000"),
    ("malformed_too_long", "malformed", "https://example.com/" + "a" * 9000),
    ("scheme_relative", "scheme", "//example.com/path"),
    ("scheme_javascript", "scheme", "javascript:alert(1)"),
    ("scheme_file", "scheme", "file:///etc/passwd"),
    ("scheme_content", "scheme", "content://media/external/images/1"),
    ("scheme_intent", "scheme", "intent://scan/#Intent;scheme=zxing;end"),
    ("scheme_data", "scheme", "data:text/html,<script>alert(1)</script>"),
    ("scheme_ftp", "scheme", "ftp://example.com/file"),
    ("scheme_ws", "scheme", "ws://example.com/socket"),
    ("crlf_percent_encoded", "injection", "https://example.com/%0d%0aSet-Cookie:x"),
    ("crlf_raw", "injection", "https://example.com/\r\nSet-Cookie:x"),
)

BRAND_CASES: tuple[str, ...] = (
    "https://google.com.attacker.example/",
    "https://accounts.google.com/",
    "https://google-login.example/",
    "https://google.example.com/",
    "https://apple.com.attacker.example/",
    "https://paypa1.example/",
    "https://micros0ft.example/",
    "https://gοοgle.com/",
    "https://paypal.com.evil.com/",
    "https://example.com/paypal",
    "https://example.com/?q=paypal",
    "https://example.com/page#paypal",
)

SHORTENER_CASES: tuple[str, ...] = (
    "https://bit.ly/abc",
    "https://go.bit.ly/xyz",
    "https://sub.t.co/xyz",
    "https://fake-shortener.example/",
    "https://bit.ly.attacker.example/abc",
    "https://bit-ly.example/abc",
    "https://example.com/bit.ly/abc",
    "https://youtu.be/abc",
)


def url_outcome(raw: str) -> dict[str, Any]:
    outcome, scheme = classify_scheme(raw)
    record: dict[str, Any] = {"schemeOutcome": outcome.value, "scheme": scheme}
    if outcome is SchemeOutcome.MALFORMED:
        record["outcome"] = "MALFORMED"
        return record
    try:
        normalized = normalize_url(raw)
    except URLNormalizationError as error:
        if outcome is SchemeOutcome.UNSUPPORTED_SCHEME or "Only HTTP and HTTPS" in str(error):
            record["outcome"] = "UNSUPPORTED_SCHEME"
            record["detail"] = str(error)
        else:
            record["outcome"] = "MALFORMED"
            record["detail"] = str(error)
        return record
    record["outcome"] = "ACCEPTED"
    record["normalizedUrl"] = normalized.normalized_url
    record["hostname"] = normalized.hostname
    record["registrableDomain"] = normalized.registrable_domain
    return record


def build_corpus() -> dict[str, Any]:
    brand_engine = BrandDetectionEngine()
    shortener_engine = ShortenerDetectionEngine()
    url_cases = []
    for case_id, category, raw in URL_CASES:
        url_cases.append({"id": case_id, "category": category, "input": raw, **url_outcome(raw)})
    brand_cases = []
    for raw in BRAND_CASES:
        assessment = brand_engine.assess(normalize_url(raw))
        brand_cases.append({
            "input": raw,
            "expectedDetected": assessment.detected,
            "expectedOfficialDomain": assessment.official_domain,
            "expectedDomainMismatch": assessment.domain_mismatch,
            "expectedRiskScore": assessment.risk_score,
            "expectedBrands": sorted(
                [{"brandId": match.brand_id, "location": match.location, "confusable": match.confusable}
                 for match in assessment.brands],
                key=lambda item: (item["brandId"], item["location"]),
            ),
        })
    shortener_cases = []
    for raw in SHORTENER_CASES:
        assessment = shortener_engine.assess(normalize_url(raw))
        shortener_cases.append({
            "input": raw,
            "expectedDetected": assessment.detected,
            "expectedDomain": assessment.domain,
        })
    unsupported = [case for case in url_cases if case["outcome"] == "UNSUPPORTED_SCHEME"]
    return {
        "corpusVersion": CORPUS_VERSION,
        "generatedAt": GENERATED_AT,
        "urlCaseCount": len(url_cases),
        "brandCaseCount": len(brand_cases),
        "shortenerCaseCount": len(shortener_cases),
        "unsupportedSchemeCount": len(unsupported),
        "urlCases": url_cases,
        "brandCases": brand_cases,
        "shortenerCases": shortener_cases,
    }


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    corpus = build_corpus()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(corpus, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "corpusVersion": corpus["corpusVersion"],
        "urlCaseCount": corpus["urlCaseCount"],
        "brandCaseCount": corpus["brandCaseCount"],
        "shortenerCaseCount": corpus["shortenerCaseCount"],
        "unsupportedSchemeCount": corpus["unsupportedSchemeCount"],
        "output": str(OUTPUT),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
