from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.deployment.export_android import MAX_LENGTH, POLICY_THRESHOLDS, ROOT, _fixtures


def test_android_golden_set_has_required_coverage():
    fixtures = _fixtures()
    assert len(fixtures) >= 50
    joined = "\n".join(fixtures).lower()
    for marker in ("xn--", "192.0.2.", "login", "verify", "?", "-"):
        assert marker in joined


def test_android_deployment_contract_is_frozen():
    assert MAX_LENGTH == 32
    assert POLICY_THRESHOLDS.review_at == 0.35
    assert POLICY_THRESHOLDS.block_at == 0.85


def test_android_deployment_manifest_and_asset_hashes_are_consistent():
    directory = ROOT / "deployment" / "android" / "v1"
    manifest = json.loads((directory / "deployment_manifest.json").read_text(encoding="utf-8"))
    assert manifest["appVersion"] == "0.8.0"
    assert manifest["app"]["defaultDecisionEngine"] == "DecisionPolicyV1"
    assert manifest["policy"]["ugdmEnabled"] is False
    assert manifest["parity"]["classAgreement"] == 1.0
    for name, expected in manifest["assets"].items():
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        assert actual == expected, name


def test_android_frozen_threat_intelligence_contract():
    directory = ROOT / "deployment" / "android" / "v1"
    manifest = json.loads((directory / "deployment_manifest.json").read_text(encoding="utf-8"))
    lines = (directory / "threat_intel_sha256.txt").read_text(encoding="ascii").splitlines()
    assert len(lines) == 7_833
    assert len(set(lines)) == 7_833
    assert all(len(item) == 64 for item in lines)
    assert manifest["threatIntelligence"]["snapshotFileSHA256"] == (
        "c1007b9b9c8e2f4b7ead01822a2c297aead232c3534fbd68d6fb5f52d53d70fe"
    )
