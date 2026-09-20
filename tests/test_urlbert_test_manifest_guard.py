"""Frozen Test Manifest guard tests.

The guard must stop the experiment whenever the sealed Test Set changes, and it
must never rewrite or redraw anything.
"""

import json

import pytest

from src.data.snapshot import sha256_file
from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.dataset import DatasetContractError, verify_frozen_test_manifest


def test_manifest_guard_accepts_the_untampered_freeze(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    manifest = verify_frozen_test_manifest(config, verify_test_files=True)
    assert manifest["datasetVersion"] == config.dataset_version
    assert manifest["views"]["domain_only"]["record_count"] > 0


def test_manifest_guard_rejects_a_changed_manifest_hash(frozen_dataset_factory):
    import yaml

    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    manifest_path = config.raw_path("test_manifest")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["creationTime"] = "2099-01-01T00:00:00+00:00"
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    with pytest.raises(DatasetContractError, match="SHA-256"):
        verify_frozen_test_manifest(config, verify_test_files=False)


def test_manifest_guard_rejects_a_changed_test_csv(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    test_path = config.splits_dir / "test.csv"
    original = test_path.read_text(encoding="utf-8")
    test_path.write_text(original.replace("benign-test", "benign-edit", 1), encoding="utf-8")
    with pytest.raises(DatasetContractError, match="Test CSV"):
        verify_frozen_test_manifest(config, verify_test_files=True)


def test_manifest_guard_never_modifies_the_sealed_files(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    manifest_path = config.raw_path("test_manifest")
    test_path = config.splits_dir / "test.csv"
    manifest_before = sha256_file(manifest_path)
    test_before = sha256_file(test_path)
    with pytest.raises(DatasetContractError):
        broken = load_urlbert_config(fixture["config_path"])
        object.__setattr__(broken, "raw", {**broken.raw, "expected_test_sha256": "0" * 64})
        verify_frozen_test_manifest(broken, verify_test_files=False)
    assert sha256_file(manifest_path) == manifest_before
    assert sha256_file(test_path) == test_before


def test_missing_manifest_stops_the_experiment(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    config.raw_path("test_manifest").unlink()
    with pytest.raises(DatasetContractError, match="missing"):
        verify_frozen_test_manifest(config, verify_test_files=False)
