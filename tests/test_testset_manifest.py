import pytest
import pandas as pd

from src.data.manifest import (
    build_test_manifest,
    create_or_verify_test_manifest,
    seal_test_manifest,
    verify_test_manifest_candidate,
)


def test_testset_manifest_is_created_and_rejects_redraw(tmp_path):
    test = tmp_path / "test.csv"
    pd.DataFrame({"registrable_domain": ["example.com"], "label": ["BENIGN"]}).to_csv(test, index=False)
    manifest = tmp_path / "test_manifest.json"
    first = create_or_verify_test_manifest(manifest, "dataset-v1.0.0", {"domain_only": test})
    assert first["views"]["domain_only"]["record_count"] == 1
    pd.DataFrame({"registrable_domain": ["example.net"], "label": ["BENIGN"]}).to_csv(test, index=False)
    with pytest.raises(RuntimeError, match="sealed test set"):
        create_or_verify_test_manifest(manifest, "dataset-v1.0.0", {"domain_only": test})


def test_candidate_manifest_is_checked_before_sealed_test_is_replaced(tmp_path):
    original = pd.DataFrame({"registrable_domain": ["example.com"], "label": ["BENIGN"]})
    changed = pd.DataFrame({"registrable_domain": ["example.net"], "label": ["BENIGN"]})
    manifest_path = tmp_path / "test_manifest.json"
    seal_test_manifest(manifest_path, build_test_manifest("dataset-v1", {"domain_only": original}, 42))
    sealed_bytes = original.to_csv(index=False, lineterminator="\n").encode("utf-8")
    test_path = tmp_path / "test.csv"
    test_path.write_bytes(sealed_bytes)
    with pytest.raises(RuntimeError, match="sealed test set"):
        verify_test_manifest_candidate(
            manifest_path, build_test_manifest("dataset-v1", {"domain_only": changed}, 42)
        )
    assert test_path.read_bytes() == sealed_bytes
