"""dataset-v1.3.0 binary contract tests: mapping, leakage and frozen manifest."""

import json
from pathlib import Path

import pandas as pd
import pytest

from src.data.snapshot import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[1]
V13_SPLITS = REPO_ROOT / "data" / "splits" / "v1.3.0" / "binary"
V13_MANIFEST = REPO_ROOT / "data" / "splits" / "v1.3.0" / "test_manifest_v1.3.0.json"
V13_METADATA = REPO_ROOT / "data" / "processed" / "v1.3.0" / "dataset_metadata.json"
BINARY_MAPPING = {"BENIGN": 0, "PHISHING": 1}


def _require_workspace():
    if not V13_MANIFEST.exists():
        pytest.skip("dataset-v1.3.0 is not built in this environment")


def test_binary_label_space_is_benign_phishing_only():
    _require_workspace()
    metadata = json.loads(V13_METADATA.read_text(encoding="utf-8"))
    assert metadata["task"] == "binary_phishing"
    assert metadata["labelMapping"] == BINARY_MAPPING
    assert metadata["labelSpace"] == ["BENIGN", "PHISHING"]
    assert "MALWARE" not in metadata["labelSpace"]


def test_binary_splits_only_contain_the_two_labels():
    _require_workspace()
    for split in ("train", "validation", "test"):
        frame = pd.read_csv(V13_SPLITS / f"{split}.csv", dtype=str, low_memory=False)
        assert set(frame["label"].astype(str)) == {"BENIGN", "PHISHING"}, split
        assert set(frame["binary_label"].astype(str)) == {"0", "1"}, split


def test_binary_label_column_matches_the_mapping():
    _require_workspace()
    frame = pd.read_csv(V13_SPLITS / "test.csv", dtype=str, low_memory=False)
    expected = frame["label"].map(BINARY_MAPPING).astype(str)
    assert frame["binary_label"].astype(str).tolist() == expected.tolist()


def test_malware_is_recorded_as_threat_intelligence_scope():
    _require_workspace()
    metadata = json.loads(V13_METADATA.read_text(encoding="utf-8"))
    handling = metadata["malwareHandling"]
    assert handling["threatIntelligenceProviders"] == ["URLHAUS", "THREATFOX"]
    assert handling["excludedRawRows"] > 0
    assert set(handling["excludedSources"]).issubset({"urlhaus", "threatfox"})


def test_binary_domain_leakage_is_zero():
    _require_workspace()
    frames = {
        split: pd.read_csv(V13_SPLITS / f"{split}.csv", dtype=str, low_memory=False)
        for split in ("train", "validation", "test")
    }
    sets = {name: set(frame["registrable_domain"]) for name, frame in frames.items()}
    assert not sets["train"] & sets["validation"]
    assert not sets["train"] & sets["test"]
    assert not sets["validation"] & sets["test"]


def test_binary_frozen_manifest_matches_the_sealed_test_file():
    _require_workspace()
    manifest = json.loads(V13_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["datasetVersion"] == "dataset-v1.3.0"
    assert manifest["labelSpace"] == BINARY_MAPPING
    entry = manifest["views"]["binary"]
    test_path = V13_SPLITS / "test.csv"
    assert sha256_file(test_path) == entry["sha256"]
    frame = pd.read_csv(test_path, dtype=str, low_memory=False)
    assert len(frame) == entry["record_count"]


def test_binary_dataset_does_not_reuse_the_legacy_test_allocation():
    _require_workspace()
    legacy = REPO_ROOT / "data" / "splits" / "domain_only" / "test.csv"
    if not legacy.exists():
        pytest.skip("legacy v1.1.0 workspace is not present")
    legacy_domains = set(pd.read_csv(legacy, dtype=str, low_memory=False)["registrable_domain"])
    binary_test = pd.read_csv(V13_SPLITS / "test.csv", dtype=str, low_memory=False)
    binary_domains = set(binary_test["registrable_domain"])
    # The binary dataset is a different task and version, so its Test Set must not
    # be a copy of the legacy three-class allocation.
    assert binary_domains != legacy_domains
    manifest = json.loads(V13_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["views"]["binary"]["sha256"] != (
        "f2a087792d9ba72f8d4d2e44dbabb18f40c0a2f32c626fca5efd959ec702dcc5"
    )


def test_binary_sources_are_balanced_across_phishing_feeds():
    _require_workspace()
    metadata = json.loads(V13_METADATA.read_text(encoding="utf-8"))
    share = metadata["sampling"]["phishing"]["sampledShare"]
    assert len(share) >= 3, "phishing must not come from a single source"
    assert max(share.values()) <= 0.5 + 1e-9
    assert metadata["sampling"]["phishing"]["syntheticRowsCreated"] == 0
    assert metadata["sampling"]["phishing"]["duplicateRowsCreated"] == 0


def test_cross_source_conflict_audit_is_recorded():
    _require_workspace()
    metadata = json.loads(V13_METADATA.read_text(encoding="utf-8"))
    audit = metadata["crossSourceConflictAudit"]
    assert "conflictingNormalizedUrls" in audit
    assert "domainsListedByMultiplePhishingSources" in audit
    assert "excluded" in audit["rule"].lower()


def test_openphish_accumulation_reports_deduplication():
    _require_workspace()
    metadata = json.loads(V13_METADATA.read_text(encoding="utf-8"))
    accumulation = metadata["openphishAccumulation"]
    assert accumulation["snapshotCount"] >= 1
    assert accumulation["uniqueNormalizedUrls"] <= accumulation["totalRawRecords"]
    assert "counted once" in accumulation["deduplicationRule"]
