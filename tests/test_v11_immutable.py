"""dataset-v1.1.0 must remain byte-for-byte untouched by Phase 2.5."""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LEGACY_MANIFEST = REPO_ROOT / "data" / "splits" / "test_manifest.json"
LEGACY_TEST = REPO_ROOT / "data" / "splits" / "domain_only" / "test.csv"
LEGACY_METADATA = REPO_ROOT / "data" / "processed" / "metadata" / "dataset-v1.0.0.json"

EXPECTED_MANIFEST_SHA256 = "21b7b7284f5d207beb4d4d673fc0471e38e92fef0a15d278710ff5bedd596e20"
EXPECTED_TEST_SHA256 = "f2a087792d9ba72f8d4d2e44dbabb18f40c0a2f32c626fca5efd959ec702dcc5"
EXPECTED_V11_METADATA_VERSION = "dataset-v1.1.0"


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_legacy_test_manifest_hash_is_unchanged():
    if not LEGACY_MANIFEST.exists():
        pytest.skip("Legacy v1.1.0 workspace is not present in this environment")
    assert _sha256(LEGACY_MANIFEST) == EXPECTED_MANIFEST_SHA256


def test_legacy_test_csv_hash_is_unchanged():
    if not LEGACY_TEST.exists():
        pytest.skip("Legacy v1.1.0 workspace is not present in this environment")
    assert _sha256(LEGACY_TEST) == EXPECTED_TEST_SHA256


def test_legacy_manifest_is_labelled_a_legacy_benchmark():
    if not LEGACY_MANIFEST.exists():
        pytest.skip("Legacy v1.1.0 workspace is not present in this environment")
    manifest = json.loads(LEGACY_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["datasetVersion"] == EXPECTED_V11_METADATA_VERSION
    assert manifest["views"]["domain_only"]["sha256"] == EXPECTED_TEST_SHA256


def test_v12_build_never_writes_into_v11_paths():
    """The v1.2.0 builder must only touch versioned v1.2.0 output paths."""

    source = (REPO_ROOT / "src" / "data" / "dataset_v12.py").read_text(encoding="utf-8")
    for forbidden in (
        '"data/splits/test_manifest.json"',
        '"data/splits/domain_only"',
        'data/splits/domain_only/test.csv',
        '"data/processed/dataset_metadata.json"',
    ):
        assert forbidden not in source
    assert "data/splits/v1.2.0" in source
    assert "data/processed/v1.2.0" in source


def test_v11_metadata_history_is_still_present():
    if not LEGACY_METADATA.exists():
        pytest.skip("Legacy metadata history is not present in this environment")
    payload = json.loads(LEGACY_METADATA.read_text(encoding="utf-8"))
    assert payload["datasetVersion"] == "dataset-v1.0.0"
