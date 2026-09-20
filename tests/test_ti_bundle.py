import hashlib
import json

import pytest

from src.intel.bundle import (
    BUNDLE_VERSION,
    build_bundle,
    bundle_summary,
    canonical_json,
    payload_digest,
    verify_bundle,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_bundle_round_trip_verifies() -> None:
    bundle = build_bundle([digest("a.example"), digest("b.example")], created_at="2026-09-20")
    verification = verify_bundle(bundle)
    assert verification.ok, verification.reason
    summary = bundle_summary(bundle)
    assert summary["bundleVersion"] == BUNDLE_VERSION
    assert summary["indicatorCount"] == 2
    assert summary["brandCount"] > 0
    assert summary["shortenerCount"] > 0


def test_payload_tampering_is_detected() -> None:
    bundle = build_bundle([digest("a.example")], created_at="2026-09-20")
    bundle["payload"]["threatIntel"]["indicatorDigests"].append(digest("evil.example"))
    verification = verify_bundle(bundle)
    assert not verification.ok
    assert verification.reason == "integrity_digest_mismatch"


def test_wrong_bundle_version_is_rejected() -> None:
    bundle = build_bundle([digest("a.example")], created_at="2026-09-20")
    bundle["bundleVersion"] = "ti-bundle-v0"
    assert verify_bundle(bundle).reason == "unsupported_bundle_version"


def test_canonical_json_is_key_order_independent() -> None:
    left = {"b": 1, "a": {"d": [1, 2], "c": "x"}}
    right = {"a": {"c": "x", "d": [1, 2]}, "b": 1}
    assert canonical_json(left) == canonical_json(right)
    assert payload_digest(left) == payload_digest(right)


def test_non_ascii_payload_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_bundle([digest("a.example")], created_at="2026-09-20", brand_payload={"entries": ["壞"]})


def test_float_payload_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_bundle([digest("a.example")], created_at="2026-09-20", brand_payload={"entries": [1.5]})


def test_invalid_indicator_digest_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_bundle(["not-a-digest"], created_at="2026-09-20")


def test_bundle_json_is_stable_across_writes() -> None:
    bundle = build_bundle([digest("a.example")], created_at="2026-09-20")
    assert json.loads(json.dumps(bundle))["integrity"]["canonicalDigest"] == bundle["integrity"]["canonicalDigest"]
