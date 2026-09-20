"""dataset-v1.2.0 contract tests: manifest, host-type audit and sampling regimes."""

import json
from pathlib import Path

import pandas as pd
import pytest

from src.data.hosttype import (
    DOMAIN,
    IPV4,
    classify_host_type,
    host_type_counts,
)
from src.data.snapshot import sha256_file

REPO_ROOT = Path(__file__).resolve().parents[1]
V12_SPLITS = REPO_ROOT / "data" / "splits" / "v1.2.0"
V12_MANIFEST = V12_SPLITS / "test_manifest_v1.2.0.json"
V12_METADATA = REPO_ROOT / "data" / "processed" / "v1.2.0" / "dataset_metadata.json"


def _require_workspace():
    if not V12_MANIFEST.exists():
        pytest.skip("dataset-v1.2.0 is not built in this environment")


def test_v12_manifest_declares_both_regimes_and_a_primary_regime():
    _require_workspace()
    manifest = json.loads(V12_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["datasetVersion"] == "dataset-v1.2.0"
    assert manifest["primaryRegime"] == "artifact_controlled"
    assert set(manifest["views"]) == {"artifact_controlled", "natural"}
    assert "combinedTestSetSha256" in manifest


def test_v12_sealed_test_files_match_the_manifest():
    _require_workspace()
    manifest = json.loads(V12_MANIFEST.read_text(encoding="utf-8"))
    for regime, entry in manifest["views"].items():
        path = V12_SPLITS / regime / "test.csv"
        assert path.exists(), regime
        assert sha256_file(path) == entry["sha256"], regime
        frame = pd.read_csv(path, dtype=str, low_memory=False)
        assert len(frame) == entry["record_count"], regime


def test_v12_primary_regime_is_the_artifact_controlled_test():
    _require_workspace()
    manifest = json.loads(V12_MANIFEST.read_text(encoding="utf-8"))
    metadata = json.loads(V12_METADATA.read_text(encoding="utf-8"))
    assert metadata["primaryRegime"] == manifest["primaryRegime"]
    assert metadata["testManifestSHA256"] == sha256_file(V12_MANIFEST)


def test_v12_splits_have_zero_domain_leakage():
    _require_workspace()
    for regime in ("artifact_controlled", "natural"):
        frames = {
            split: pd.read_csv(V12_SPLITS / regime / f"{split}.csv", dtype=str, low_memory=False)
            for split in ("train", "validation", "test")
        }
        sets = {name: set(frame["registrable_domain"]) for name, frame in frames.items()}
        assert not sets["train"] & sets["validation"], regime
        assert not sets["train"] & sets["test"], regime
        assert not sets["validation"] & sets["test"], regime


def test_v12_host_type_column_is_present_and_never_a_feature():
    _require_workspace()
    frame = pd.read_csv(V12_SPLITS / "artifact_controlled" / "test.csv", dtype=str, low_memory=False)
    assert "host_type" in frame.columns
    assert set(frame["host_type"].dropna().unique()).issubset({"DOMAIN", "IPV4", "IPV6"})
    from src.features.schema import FEATURE_NAMES

    assert "host_type" not in FEATURE_NAMES


def test_artifact_controlled_balances_ip_and_domain_malware():
    _require_workspace()
    metadata = json.loads(V12_METADATA.read_text(encoding="utf-8"))
    rationale = metadata["regimeDetails"]["artifact_controlled"]["samplingRationale"]["malwareControl"]
    assert rationale["syntheticRowsCreated"] == 0
    assert rationale["duplicateRowsCreated"] == 0
    assert rationale["ipHostRecordsKept"] == rationale["domainHostRecords"]
    assert rationale["resultingIpShare"] == pytest.approx(0.5, abs=1e-9)
    assert rationale["ipHostRecordsAvailable"] > rationale["ipHostRecordsKept"]


def test_natural_regime_preserves_the_source_host_type_distribution():
    _require_workspace()
    metadata = json.loads(V12_METADATA.read_text(encoding="utf-8"))
    natural = metadata["regimeDetails"]["natural"]["samplingRationale"]
    controlled = metadata["regimeDetails"]["artifact_controlled"]["samplingRationale"]
    natural_ip_share = natural["malwareHostTypeShare"]["IPV4"]
    controlled_ip_share = controlled["malwareHostTypeShare"]["IPV4"]
    assert natural_ip_share > controlled_ip_share
    assert natural["malwareHostTypeCounts"]["IPV4"] > natural["malwareHostTypeCounts"]["DOMAIN"]


def test_host_type_classification_covers_all_three_cases():
    assert classify_host_type("example.com") == DOMAIN
    assert classify_host_type("192.0.2.1") == IPV4
    assert classify_host_type("2001:db8::1") == "IPV6"
    assert classify_host_type("[2001:db8::1]") == "IPV6"
    assert classify_host_type("") == DOMAIN
    counts = host_type_counts(pd.DataFrame({"registrable_domain": ["a.com", "192.0.2.1", "2001:db8::1"]}))
    assert counts == {"DOMAIN": 1, "IPV4": 1, "IPV6": 1}


def test_malware_ip_artifact_audit_records_every_stage():
    _require_workspace()
    metadata = json.loads(V12_METADATA.read_text(encoding="utf-8"))
    audit = metadata["malwareIpArtifactAudit"]
    stages = {stage["stage"]: stage for stage in audit["stages"]}
    assert set(stages) == {"raw_union", "after_cleaning", "after_domain_only_dedup"}
    for stage in stages.values():
        assert set(stage["hostTypeShare"]) == {"DOMAIN", "IPV4", "IPV6"}
    assert stages["after_domain_only_dedup"]["hostTypeShare"]["IPV4"] > 0
    assert "conclusion" in audit
