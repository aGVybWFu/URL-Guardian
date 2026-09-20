"""TI Bundle v1: versioned, integrity-checked offline intelligence bundle.

The bundle carries the frozen threat-intelligence digests plus the brand and
shortener catalogs in one deterministic JSON document. Integrity is a SHA-256
digest over a canonical JSON serialisation of `payload` (sorted keys, no
whitespace, ASCII-only data), which the Android importer reproduces exactly.

The bundle is data only. Importing it can never enable network access, and a
bundle that fails verification is rejected without touching the active one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from src.intel.catalogs import brand_catalog_payload, shortener_catalog_payload

BUNDLE_VERSION = "ti-bundle-v1"
INTEGRITY_ALGORITHM = "sha256"
DIGEST_ALGORITHM = "sha256"
DEFAULT_POLICY_VERSION = "DecisionPolicyV2"


def canonical_json(payload: Any) -> str:
    """Canonical serialisation shared with the Kotlin importer."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()


def _assert_ascii(value: Any, path: str = "payload") -> None:
    if isinstance(value, str):
        if not value.isascii():
            raise ValueError(f"bundle payload must be ASCII-only: {path}")
    elif isinstance(value, bool) or isinstance(value, int):
        return
    elif isinstance(value, float):
        raise ValueError(f"bundle payload must not contain floats: {path}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_ascii(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not str(key).isascii():
                raise ValueError(f"bundle payload must be ASCII-only: {path}.{key}")
            _assert_ascii(item, f"{path}.{key}")
    elif value is None:
        return
    else:
        raise ValueError(f"bundle payload contains an unsupported type: {path}")


def build_payload(
    indicator_digests: Iterable[str],
    brand_payload: dict[str, Any] | None = None,
    shortener_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    digests = sorted({str(item).lower() for item in indicator_digests})
    for digest in digests:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("indicator digests must be lowercase SHA-256 hex strings")
    payload = {
        "threatIntel": {
            "digestAlgorithm": DIGEST_ALGORITHM,
            "indicatorCount": len(digests),
            "indicatorDigests": digests,
        },
        "brands": brand_payload if brand_payload is not None else brand_catalog_payload(),
        "shorteners": shortener_payload if shortener_payload is not None else shortener_catalog_payload(),
    }
    _assert_ascii(payload)
    return payload


def build_bundle(
    indicator_digests: Iterable[str],
    created_at: str,
    policy_version: str = DEFAULT_POLICY_VERSION,
    brand_payload: dict[str, Any] | None = None,
    shortener_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = build_payload(indicator_digests, brand_payload, shortener_payload)
    bundle = {
        "bundleVersion": BUNDLE_VERSION,
        "createdAt": created_at,
        "policyVersion": policy_version,
        "payload": payload,
        "integrity": {"algorithm": INTEGRITY_ALGORITHM, "canonicalDigest": payload_digest(payload)},
    }
    _assert_ascii({"bundleVersion": bundle["bundleVersion"], "createdAt": created_at, "policyVersion": policy_version})
    return bundle


@dataclass(frozen=True)
class BundleVerification:
    ok: bool
    reason: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason, "digest": self.digest}


def verify_bundle(bundle: Any) -> BundleVerification:
    if not isinstance(bundle, dict):
        return BundleVerification(False, "bundle_not_an_object", "")
    if bundle.get("bundleVersion") != BUNDLE_VERSION:
        return BundleVerification(False, "unsupported_bundle_version", "")
    payload = bundle.get("payload")
    if not isinstance(payload, dict):
        return BundleVerification(False, "missing_payload", "")
    integrity = bundle.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != INTEGRITY_ALGORITHM:
        return BundleVerification(False, "missing_integrity_block", "")
    expected = str(integrity.get("canonicalDigest", ""))
    try:
        actual = payload_digest(payload)
    except (TypeError, ValueError):
        return BundleVerification(False, "payload_not_canonicalisable", "")
    if actual != expected:
        return BundleVerification(False, "integrity_digest_mismatch", actual)
    threat_intel = payload.get("threatIntel")
    brands = payload.get("brands")
    shorteners = payload.get("shorteners")
    if not isinstance(threat_intel, dict) or not isinstance(brands, dict) or not isinstance(shorteners, dict):
        return BundleVerification(False, "missing_payload_sections", actual)
    digests = threat_intel.get("indicatorDigests")
    if not isinstance(digests, list) or int(threat_intel.get("indicatorCount", -1)) != len(digests):
        return BundleVerification(False, "indicator_count_mismatch", actual)
    if not isinstance(brands.get("entries"), list) or not isinstance(shorteners.get("domains"), list):
        return BundleVerification(False, "catalog_payload_invalid", actual)
    return BundleVerification(True, "ok", actual)


def write_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(bundle, ensure_ascii=True, indent=2) + "\n", encoding="ascii", newline="\n")


def read_bundle(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def bundle_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    payload = bundle.get("payload", {})
    threat_intel = payload.get("threatIntel", {})
    brands = payload.get("brands", {})
    shorteners = payload.get("shorteners", {})
    return {
        "bundleVersion": bundle.get("bundleVersion"),
        "createdAt": bundle.get("createdAt"),
        "policyVersion": bundle.get("policyVersion"),
        "indicatorCount": int(threat_intel.get("indicatorCount", 0)),
        "brandCount": int(brands.get("entryCount", len(brands.get("entries", [])))),
        "shortenerCount": int(shorteners.get("domainCount", len(shorteners.get("domains", [])))),
        "canonicalDigest": bundle.get("integrity", {}).get("canonicalDigest"),
    }
