"""Desktop TI Bundle v1 builder.

Reads the frozen threat-intelligence snapshot and the curated catalogs, builds a
deterministic bundle and verifies it before it can be shipped as an Android
asset. The builder is offline and never touches a URL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.intel.bundle import build_bundle, bundle_summary, verify_bundle, write_bundle

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "data" / "processed" / "ugdm-v1.0.0" / "threat_intel_snapshot.json"
BUNDLE_CREATED_AT = "2026-09-20"
BUNDLE_FILE_NAME = "ti_bundle.json"


def load_frozen_digests(snapshot: Path = SNAPSHOT) -> list[str]:
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    digests = sorted({str(item) for item in payload["indicatorDigests"]})
    if len(digests) != int(payload["indicatorCount"]):
        raise RuntimeError("frozen TI snapshot count mismatch")
    return digests


def build_bundle_from_frozen_snapshot(
    created_at: str = BUNDLE_CREATED_AT,
    policy_version: str = "DecisionPolicyV2",
    snapshot: Path = SNAPSHOT,
) -> dict[str, Any]:
    bundle = build_bundle(load_frozen_digests(snapshot), created_at=created_at, policy_version=policy_version)
    verification = verify_bundle(bundle)
    if not verification.ok:
        raise RuntimeError(f"built bundle failed verification: {verification.reason}")
    return bundle


def write_bundle_asset(output_dir: str | Path, bundle: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle = bundle if bundle is not None else build_bundle_from_frozen_snapshot()
    write_bundle(Path(output_dir) / BUNDLE_FILE_NAME, bundle)
    return bundle_summary(bundle)
