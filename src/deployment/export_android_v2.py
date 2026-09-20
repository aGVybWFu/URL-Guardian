"""Export the Phase 5 android-v2 deployment assets.

The frozen Phase 4 artifacts (ONNX model, tokenizer, public suffixes, threat
intelligence index, golden set) are copied byte-for-byte from
`deployment/android/v1` and their hashes are re-checked against the v1 manifest.
Only new or policy-versioned files are generated:

* `ti_bundle.json` - TI Bundle v1 with integrity digest.
* `policy_v2_golden.json` - DecisionPolicyV2 expectations for the frozen fixtures.
* `feature_schema.json` - v2 availability/source for the Phase 5 signals.
* `decision_policy.json` - DecisionPolicyV2 contract (V1 stays the frozen record).
* `deployment_manifest.json` - android-v2 manifest.

The exporter is offline, does not re-export the ONNX model and does not import
torch.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from src.data.normalizer import normalize_url
from src.deployment.ti_bundle_builder import build_bundle_from_frozen_snapshot, write_bundle_asset
from src.intel.brand_engine import BrandDetectionEngine
from src.intel.shortener_engine import ShortenerDetectionEngine
from src.policy.v2 import BRAND_SCORE_REVIEW_AT, POLICY_VERSION_V2, ReasonCode, V2_THRESHOLDS, decide_v2
from src.ugdm.features import default_availability, feature_spec_payload

ROOT = Path(__file__).resolve().parents[2]
V1_OUTPUT = ROOT / "deployment" / "android" / "v1"
V2_OUTPUT = ROOT / "deployment" / "android" / "v2"
DEPLOYMENT_VERSION_V2 = "android-v2"
APP_VERSION = "1.0.0"

FROZEN_FILES = (
    "urlbert_binary.onnx",
    "tokenizer.json",
    "public_suffixes.txt",
    "threat_intel_sha256.txt",
    "golden_set.json",
    "parity_report.json",
    "output_schema.json",
)

V2_IMPLEMENTED_FEATURES = {
    "brand_detected": ("ALWAYS", "src.intel.brand_engine", "Catalog-based brand token detection; heuristic, not a guarantee."),
    "brand_domain_mismatch": ("ALWAYS", "src.intel.brand_engine", "Brand token on a non-official registrable domain."),
    "brand_risk_score": ("ALWAYS", "src.intel.brand_engine", "0 for the brand's own canonical domain; confusable matches score higher."),
    "redirect_count": (
        "CONDITIONAL",
        "src.intel.redirect",
        "Only available when a resolver observed the chain; NoOpRedirectResolver reports NOT_OBSERVED.",
    ),
    "cross_domain_redirect": (
        "CONDITIONAL",
        "src.intel.redirect",
        "Only available when a resolver observed the chain; NoOpRedirectResolver reports NOT_OBSERVED.",
    ),
    "shortener_detected": ("ALWAYS", "src.intel.shortener_engine", "Catalog-based shortener domain detection; reviews, never blocks alone."),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_frozen_assets() -> dict[str, Any]:
    V2_OUTPUT.mkdir(parents=True, exist_ok=True)
    v1_manifest = json.loads((V1_OUTPUT / "deployment_manifest.json").read_text(encoding="utf-8"))
    for name in FROZEN_FILES:
        shutil.copyfile(V1_OUTPUT / name, V2_OUTPUT / name)
    checks = {
        "onnx": sha256_file(V2_OUTPUT / "urlbert_binary.onnx") == v1_manifest["model"]["onnxSHA256"],
        "tokenizer": sha256_file(V2_OUTPUT / "tokenizer.json") == v1_manifest["tokenizer"]["sha256"],
        "goldenSet": sha256_file(V2_OUTPUT / "golden_set.json") == v1_manifest["assets"]["golden_set.json"],
        "publicSuffixes": sha256_file(V2_OUTPUT / "public_suffixes.txt") == v1_manifest["assets"]["public_suffixes.txt"],
        "threatIntel": sha256_file(V2_OUTPUT / "threat_intel_sha256.txt") == v1_manifest["assets"]["threat_intel_sha256.txt"],
        "parityReport": sha256_file(V2_OUTPUT / "parity_report.json") == v1_manifest["assets"]["parity_report.json"],
    }
    if not all(checks.values()):
        raise RuntimeError(f"frozen asset hash mismatch: {checks}")
    return v1_manifest


def v2_feature_schema_payload() -> dict[str, Any]:
    payload = feature_spec_payload()
    for feature in payload["features"]:
        override = V2_IMPLEMENTED_FEATURES.get(feature["name"])
        if override is not None:
            availability, source, notes = override
            feature["availability"] = availability
            feature["source"] = source
            feature["notes"] = notes
    return payload


def _policy_features(row: dict[str, Any], brand_features: dict[str, float], shortener_features: dict[str, float]) -> dict[str, float]:
    extracted = row["features"]
    features = {
        "phishing_probability": float(row["onnxProbabilities"][1]),
        "known_malicious": 0.0,
        "url_length": float(extracted["url_length"]),
        "hostname_length": float(extracted["hostname_length"]),
        "subdomain_count": float(extracted["subdomain_count"]),
        "digit_ratio": float(extracted["digit_ratio"]),
        "special_character_ratio": float(extracted["special_character_ratio"]),
        "hostname_entropy": float(extracted["hostname_entropy"]),
        "has_ip": float(extracted["has_ip_address"]),
        "has_punycode": float(extracted["has_punycode"]),
        "has_at_symbol": float(extracted["has_at_symbol"]),
        "uses_https": float(extracted["is_https"]),
        "has_non_default_port": float(extracted["has_non_default_port"]),
        **{name: float(extracted[name]) for name in (
            "contains_login", "contains_verify", "contains_secure", "contains_account",
            "contains_password", "contains_payment", "contains_wallet",
        )},
    }
    features.update(brand_features)
    features.update(shortener_features)
    return features


BRAND_CASES = (
    "https://www.paypal.com/login",
    "https://login.paypal.com/session",
    "https://fb.com/",
    "https://paypal-login.com/",
    "https://paypal.com.evil.com/",
    "https://paypa1-login.com/",
    "https://example.com/paypal/login",
    "https://applepie.example.com/",
    "https://example.com/",
)

SHORTENER_CASES = (
    "https://bit.ly/abc123",
    "https://go.bit.ly/xyz",
    "https://example.com/path",
    "https://youtu.be/abc",
)


def _availability(**overrides: bool) -> dict[str, bool]:
    base = {
        "known_malicious": False,
        "whitelist_hit": False,
        "brand_detected": False,
        "brand_domain_mismatch": False,
        "brand_risk_score": False,
        "shortener_detected": False,
        "cross_domain_redirect": False,
        "redirect_count": False,
        "contains_login": False,
    }
    base.update(overrides)
    return base


DECISION_CASES = (
    ("guardrail_official_domain", {"phishing_probability": 0.01, "known_malicious": 1.0, "brand_detected": 1.0}, _availability(known_malicious=True, brand_detected=True, brand_risk_score=True)),
    ("official_brand_low_probability", {"phishing_probability": 0.10, "brand_detected": 1.0, "brand_risk_score": 0.0}, _availability(brand_detected=True, brand_risk_score=True)),
    ("official_brand_high_probability", {"phishing_probability": 0.60, "brand_detected": 1.0, "brand_risk_score": 0.0}, _availability(brand_detected=True, brand_risk_score=True)),
    ("official_brand_with_redirect_review", {"phishing_probability": 0.10, "brand_detected": 1.0, "brand_risk_score": 0.0, "cross_domain_redirect": 1.0, "redirect_count": 2.0}, _availability(brand_detected=True, brand_risk_score=True, cross_domain_redirect=True, redirect_count=True)),
    ("brand_mismatch_block", {"phishing_probability": 0.90, "brand_detected": 1.0, "brand_domain_mismatch": 1.0, "brand_risk_score": 0.95}, _availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True)),
    ("brand_mismatch_review", {"phishing_probability": 0.50, "brand_detected": 1.0, "brand_domain_mismatch": 1.0, "brand_risk_score": 0.85}, _availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True)),
    ("brand_score_review_low_probability", {"phishing_probability": 0.05, "brand_detected": 1.0, "brand_domain_mismatch": 1.0, "brand_risk_score": 0.5}, _availability(brand_detected=True, brand_domain_mismatch=True, brand_risk_score=True)),
    ("shortener_review", {"phishing_probability": 0.05, "shortener_detected": 1.0}, _availability(shortener_detected=True)),
    ("shortener_with_evidence_block", {"phishing_probability": 0.95, "shortener_detected": 1.0, "contains_login": 1.0}, _availability(shortener_detected=True, contains_login=True)),
    ("cross_domain_redirect_review", {"phishing_probability": 0.05, "cross_domain_redirect": 1.0, "redirect_count": 3.0}, _availability(cross_domain_redirect=True, redirect_count=True)),
    ("unobserved_redirect_allow", {"phishing_probability": 0.05}, _availability()),
    ("high_probability_with_evidence", {"phishing_probability": 0.90, "contains_login": 1.0}, _availability(contains_login=True)),
    ("high_probability_without_evidence", {"phishing_probability": 0.90}, _availability()),
    ("low_risk_allow", {"phishing_probability": 0.10}, _availability()),
)


def build_phase5_parity() -> dict[str, Any]:
    brand_engine = BrandDetectionEngine()
    shortener_engine = ShortenerDetectionEngine()
    brand_cases = []
    for raw in BRAND_CASES:
        assessment = brand_engine.assess(normalize_url(raw))
        brand_cases.append({
            "input": raw,
            "expectedDetected": assessment.detected,
            "expectedOfficialDomain": assessment.official_domain,
            "expectedDomainMismatch": assessment.domain_mismatch,
            "expectedRiskScore": assessment.risk_score,
        })
    idn_host = "раypal.com".encode("idna").decode("ascii")
    idn_assessment = brand_engine.assess(normalize_url(f"https://{idn_host}/"))
    brand_cases.append({
        "input": f"https://{idn_host}/",
        "expectedDetected": idn_assessment.detected,
        "expectedOfficialDomain": idn_assessment.official_domain,
        "expectedDomainMismatch": idn_assessment.domain_mismatch,
        "expectedRiskScore": idn_assessment.risk_score,
    })
    shortener_cases = []
    for raw in SHORTENER_CASES:
        assessment = shortener_engine.assess(normalize_url(raw))
        shortener_cases.append({
            "input": raw,
            "expectedDetected": assessment.detected,
            "expectedDomain": assessment.domain,
        })
    decision_cases = []
    for name, features, availability in DECISION_CASES:
        decision = decide_v2(features, availability)
        decision_cases.append({
            "name": name,
            "features": features,
            "availability": availability,
            "expectedAction": decision.action,
            "expectedRisk": decision.risk,
            "expectedReasonCode": decision.reason_code.value,
        })
    return {
        "brandCases": brand_cases,
        "shortenerCases": shortener_cases,
        "decisionCases": decision_cases,
    }


def build_policy_v2_golden() -> dict[str, Any]:
    golden = json.loads((V2_OUTPUT / "golden_set.json").read_text(encoding="utf-8"))
    brand_engine = BrandDetectionEngine()
    shortener_engine = ShortenerDetectionEngine()
    fixtures: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    for row in golden["fixtures"]:
        normalized = normalize_url(row["input"])
        brand = brand_engine.assess(normalized)
        shortener = shortener_engine.assess(normalized)
        features = _policy_features(row, brand.to_features(), shortener.to_features())
        availability = default_availability({"URLHAUS": "AVAILABLE", "THREATFOX": "AVAILABLE"})
        availability.update(brand.availability())
        availability.update(shortener.availability())
        decision = decide_v2(features, availability)
        reason_counts[decision.reason_code.value] = reason_counts.get(decision.reason_code.value, 0) + 1
        action_counts[decision.action] = action_counts.get(decision.action, 0) + 1
        fixtures.append({
            "input": row["input"],
            "expectedAction": decision.action,
            "expectedRisk": decision.risk,
            "expectedReasonCode": decision.reason_code.value,
            "brandDetected": brand.detected,
            "brandOfficialDomain": brand.official_domain,
            "brandDomainMismatch": brand.domain_mismatch,
            "brandRiskScore": brand.risk_score,
            "shortenerDetected": shortener.detected,
            "redirectStatus": "NOT_OBSERVED",
        })
    return {
        "schemaVersion": 1,
        "policyVersion": POLICY_VERSION_V2,
        "reviewAt": V2_THRESHOLDS.review_at,
        "blockAt": V2_THRESHOLDS.block_at,
        "fixtureCount": len(fixtures),
        "actionCounts": action_counts,
        "reasonCounts": reason_counts,
        "reasonCodes": [code.value for code in ReasonCode],
        "fixtures": fixtures,
        **build_phase5_parity(),
    }


def export(output: Path = V2_OUTPUT) -> dict[str, Any]:
    global V2_OUTPUT
    V2_OUTPUT = output
    v1_manifest = copy_frozen_assets()
    bundle_summary = write_bundle_asset(output, build_bundle_from_frozen_snapshot())
    (output / "feature_schema.json").write_text(
        json.dumps(v2_feature_schema_payload(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    policy_v2_golden = build_policy_v2_golden()
    (output / "policy_v2_golden.json").write_text(
        json.dumps(policy_v2_golden, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    v1_policy = v1_manifest["policy"]
    policy = {
        "policyVersion": v1_policy["policyVersion"],
        "costVersion": v1_policy["costVersion"],
        "reviewAt": v1_policy["reviewAt"],
        "blockAt": v1_policy["blockAt"],
        "probabilityVersion": v1_policy["probabilityVersion"],
        "knownMaliciousGuardrail": v1_policy["knownMaliciousGuardrail"],
        "ugdmEnabled": v1_policy["ugdmEnabled"],
        "experimentalPolicyVersion": POLICY_VERSION_V2,
    }
    (output / "decision_policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    assets = sorted(
        path.name for path in output.iterdir() if path.is_file() and path.name != "deployment_manifest.json"
    )
    manifest = {
        "schemaVersion": 1,
        "deploymentVersion": DEPLOYMENT_VERSION_V2,
        "appVersion": APP_VERSION,
        "app": {
            "applicationId": v1_manifest["app"]["applicationId"],
            "versionName": APP_VERSION,
            "minSdk": v1_manifest["app"]["minSdk"],
            "targetSdk": v1_manifest["app"]["targetSdk"],
            "compileSdk": v1_manifest["app"]["compileSdk"],
            "abis": v1_manifest["app"]["abis"],
            "runtime": v1_manifest["app"]["runtime"],
            "defaultDecisionEngine": v1_policy["policyVersion"],
            "experimentalDecisionEngine": POLICY_VERSION_V2,
        },
        "model": v1_manifest["model"],
        "tokenizer": v1_manifest["tokenizer"],
        "threatIntelligence": v1_manifest["threatIntelligence"],
        "intelligenceBundle": {
            "file": "ti_bundle.json",
            "sha256": sha256_file(output / "ti_bundle.json"),
            **bundle_summary,
        },
        "policy": policy,
        "experimentalPolicy": {
            "policyVersion": POLICY_VERSION_V2,
            "status": "experimental",
            "default": False,
            "brandScoreReviewAt": BRAND_SCORE_REVIEW_AT,
            "note": "Optional developer/research engine; the shipped default remains DecisionPolicyV1.",
        },
        "ugdm": v1_manifest["ugdm"],
        "schemas": {"feature": 1, "output": 1},
        "publicSuffixCount": v1_manifest["publicSuffixCount"],
        "goldenFixtureCount": v1_manifest["goldenFixtureCount"],
        "parity": v1_manifest["parity"],
        "policyV2": {
            "fixtureCount": policy_v2_golden["fixtureCount"],
            "actionCounts": policy_v2_golden["actionCounts"],
            "reasonCounts": policy_v2_golden["reasonCounts"],
        },
        "assets": {name: sha256_file(output / name) for name in assets},
    }
    (output / "deployment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    manifest = export()
    print(json.dumps({
        "deploymentVersion": manifest["deploymentVersion"],
        "appVersion": manifest["appVersion"],
        "defaultDecisionEngine": manifest["app"]["defaultDecisionEngine"],
        "policyV2": manifest["policyV2"],
        "intelligenceBundle": {key: manifest["intelligenceBundle"][key] for key in (
            "bundleVersion", "createdAt", "indicatorCount", "brandCount", "shortenerCount", "canonicalDigest",
        )},
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
