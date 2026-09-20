"""Out-of-fold pipeline, threat intelligence snapshot and overlap audit tests."""

import json
from pathlib import Path

import pandas as pd
import pytest

from src.data.snapshot import sha256_file
from src.ugdm.overlap_audit import audit_overlap
from src.ugdm.oof import (
    OOF_STRATEGY,
    assert_fold_integrity,
    group_kfold_assignments,
)
from src.ugdm.threat_intel_snapshot import (
    FrozenThreatIntelSnapshot,
    indicator_digest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SPLITS_ROOT = REPO_ROOT / "data" / "splits" / "v1.3.0" / "binary"
MANIFEST = REPO_ROOT / "data" / "splits" / "v1.3.0" / "test_manifest_v1.3.0.json"
OOF_DIR = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "oof"
SNAPSHOT = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "threat_intel_snapshot.json"
DATASET = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset.csv"


def _train_frame() -> pd.DataFrame:
    path = SPLITS_ROOT / "train.csv"
    if not path.exists():
        pytest.skip("dataset-v1.3.0 is not built in this environment")
    return pd.read_csv(path, dtype=str, low_memory=False)


def test_fold_assignments_cover_every_row_exactly_once():
    frame = _train_frame()
    assignments = group_kfold_assignments(frame, n_splits=5, seed=42)
    integrity = assert_fold_integrity(frame, assignments)
    assert integrity["rowLeakage"] == 0
    assert integrity["domainOverlap"] == 0
    assert integrity["uniqueRowsCovered"] == len(frame)


def test_fold_assignments_have_zero_domain_leakage():
    frame = _train_frame()
    assignments = group_kfold_assignments(frame, n_splits=5, seed=42)
    for assignment in assignments:
        train_domains = set(frame.loc[assignment.train_index, "registrable_domain"])
        holdout_domains = set(frame.loc[assignment.holdout_index, "registrable_domain"])
        assert not train_domains & holdout_domains


def test_fold_assignments_are_deterministic():
    frame = _train_frame()
    first = group_kfold_assignments(frame, n_splits=5, seed=42)
    second = group_kfold_assignments(frame, n_splits=5, seed=42)
    assert [item.holdout_index for item in first] == [item.holdout_index for item in second]


def test_assert_fold_integrity_detects_a_missing_row():
    frame = _train_frame().head(50).reset_index(drop=True)
    assignments = group_kfold_assignments(frame, n_splits=5, seed=42)
    broken = assignments[:-1]
    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        assert_fold_integrity(frame, broken)


def test_oof_metadata_records_zero_leakage_and_full_coverage():
    path = OOF_DIR / "oof_metadata.json"
    if not path.exists():
        pytest.skip("the OOF pipeline has not been run in this environment")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["oofStrategy"] == OOF_STRATEGY
    assert payload["foldCount"] == 5
    assert payload["foldIntegrity"]["rowLeakage"] == 0
    assert payload["foldIntegrity"]["domainOverlap"] == 0
    assert payload["foldIntegrity"]["uniqueRowsCovered"] == payload["trainRowCount"]
    assert payload["testFeatureSource"].startswith("official binary checkpoint")


def test_oof_probability_tables_cover_every_split_row():
    if not OOF_DIR.exists():
        pytest.skip("the OOF pipeline has not been run in this environment")
    train = pd.read_csv(OOF_DIR / "oof_train_probabilities.csv", dtype=str, low_memory=False)
    validation = pd.read_csv(OOF_DIR / "validation_probabilities.csv", dtype=str, low_memory=False)
    test = pd.read_csv(OOF_DIR / "test_probabilities.csv", dtype=str, low_memory=False)
    assert len(train) == len(_train_frame())
    assert len(validation) == 6000
    assert len(test) == 6000
    for frame in (train, validation, test):
        probabilities = frame["phishing_probability"].astype(float)
        assert probabilities.between(0.0, 1.0).all()
        assert not frame["rowId"].duplicated().any()


def test_oof_train_rows_use_more_than_one_fold_model():
    if not OOF_DIR.exists():
        pytest.skip("the OOF pipeline has not been run in this environment")
    train = pd.read_csv(OOF_DIR / "oof_train_probabilities.csv", dtype=str, low_memory=False)
    assert train["fold"].nunique() == 5


def test_frozen_snapshot_records_provenance_and_digests():
    if not SNAPSHOT.exists():
        pytest.skip("the frozen snapshot has not been built in this environment")
    snapshot = FrozenThreatIntelSnapshot.load(SNAPSHOT)
    assert snapshot.indicator_count > 0
    payload = snapshot.payload
    assert payload["indicatorDigestAlgorithm"] == "sha256"
    assert payload["providerStatus"]["URLHAUS"] == "AVAILABLE"
    assert payload["providers"]
    for provider in payload["providers"]:
        assert provider["sha256"]
        assert provider["file"]


def test_frozen_snapshot_answers_by_digest_not_by_live_query():
    if not SNAPSHOT.exists():
        pytest.skip("the frozen snapshot has not been built in this environment")
    snapshot = FrozenThreatIntelSnapshot.load(SNAPSHOT)
    source = (REPO_ROOT / "src" / "ugdm" / "threat_intel_snapshot.py").read_text(encoding="utf-8")
    for token in ("requests.get(", "urlopen(", "socket.connect("):
        assert token not in source
    assert indicator_digest("Example.COM") == indicator_digest("example.com")


def test_frozen_snapshot_is_stable_across_reads():
    if not SNAPSHOT.exists():
        pytest.skip("the frozen snapshot has not been built in this environment")
    before = sha256_file(SNAPSHOT)
    FrozenThreatIntelSnapshot.load(SNAPSHOT)
    assert sha256_file(SNAPSHOT) == before


def test_overlap_audit_quantifies_hit_rates_by_label_and_source():
    if not SNAPSHOT.exists():
        pytest.skip("the frozen snapshot has not been built in this environment")
    test_split = SPLITS_ROOT / "test.csv"
    if not test_split.exists():
        pytest.skip("frozen DOMAIN_ONLY splits are not present in this environment")
    snapshot = FrozenThreatIntelSnapshot.load(SNAPSHOT)
    frame = pd.read_csv(test_split, dtype=str, low_memory=False)
    audit = audit_overlap(frame, snapshot)
    assert {item["label"] for item in audit["byLabel"]} == {"BENIGN", "PHISHING"}
    assert audit["bySource"]
    assert "phishingMinusBenignHitRate" in audit
    assert "ablation" in audit["interpretation"]


def test_official_overlap_audit_is_recorded_in_dataset_metadata():
    metadata_path = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset_metadata.json"
    if not metadata_path.exists():
        pytest.skip("ugdm-dataset-v1.0.0 is not built in this environment")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["threatIntelSnapshot"]["indicatorCount"] > 0
    assert metadata["threatIntelSnapshot"]["sha256"]


def test_ugdm_dataset_reuses_the_frozen_split_without_resplitting():
    if not DATASET.exists():
        pytest.skip("ugdm-dataset-v1.0.0 is not built in this environment")
    metadata = json.loads(
        (REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset_metadata.json").read_text(
            encoding="utf-8"
        )
    )
    assert metadata["sourceDatasetVersion"] == "dataset-v1.3.0"
    assert "reused unchanged" in metadata["splitAssignmentSource"]
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert metadata["testSetSHA256"] == manifest["views"]["binary"]["sha256"]
    frame = pd.read_csv(DATASET, dtype=str, low_memory=False)
    test_rows = frame[frame["split"].astype(str) == "test"]
    frozen_test = pd.read_csv(SPLITS_ROOT / "test.csv", dtype=str, low_memory=False)
    assert set(test_rows["registrable_domain"]) == set(frozen_test["registrable_domain"])
