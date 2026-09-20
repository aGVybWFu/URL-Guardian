"""Guards proving provider identity never becomes a model feature."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_FEATURE_TOKENS = (
    "source",
    "threatfox",
    "urlhaus",
    "openphish",
    "cert_polska",
    "tranco",
    "provider",
    "reporter",
    "feed",
    "label",
    "collected_at",
    "host_type",
)


def test_feature_schema_contains_no_provider_or_label_fields():
    from src.features.schema import FEATURE_NAMES

    for name in FEATURE_NAMES:
        lowered = name.lower()
        for token in ("source", "threatfox", "urlhaus", "openphish", "cert_polska", "tranco", "provider", "reporter", "label", "host_type"):
            assert token not in lowered, f"{name} looks provider- or label-derived"


def test_feature_extractor_only_reads_url_strings():
    source = (REPO_ROOT / "src" / "features" / "extractor.py").read_text(encoding="utf-8")
    for token in ("threatfox", "urlhaus", "openphish", "cert_polska", "collected_at", "host_type"):
        assert token not in source.lower()


def test_lightgbm_v2_training_uses_only_the_declared_feature_list():
    source = (REPO_ROOT / "src" / "models" / "lightgbm_v2.py").read_text(encoding="utf-8")
    assert "extract_feature_frame(train_frame[\"model_url\"])[features]" in source
    assert "extract_feature_frame(test_frame[\"model_url\"])[features]" in source
    assert "features = _feature_list(excluded)" in source
    # host_type may only select evaluation subgroups, never build a feature matrix.
    for line in source.splitlines():
        if "host_type" in line:
            assert "extract_feature_frame" not in line, line
            assert "_feature_list" not in line, line
    assert "features.append(\"host_type\")" not in source


def test_urlbert_input_is_the_frozen_registrable_domain_text():
    source = (REPO_ROOT / "src" / "models" / "urlbert" / "dataset.py").read_text(encoding="utf-8")
    assert 'config.text_column' in source
    assert "expected.eq(frame[\"model_url\"]" in source
    assert "source" not in source.split("def texts_of")[1].split("def ")[0]


def test_host_type_is_only_used_for_auditing_and_subgroups():
    for relative in (
        "src/models/lightgbm_v2.py",
        "src/models/urlbert/analysis.py",
        "src/data/dataset_v12.py",
    ):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        if "host_type" not in source:
            continue
        # host_type may select subgroups or drive auditing, but must never be
        # concatenated into a feature matrix.
        assert "FEATURE_NAMES + [\"host_type\"]" not in source
        assert "host_type\"] = extract_feature" not in source


def test_v12_metadata_declares_host_type_is_not_a_feature():
    import json

    metadata_path = REPO_ROOT / "data" / "processed" / "v1.2.0" / "dataset_metadata.json"
    if not metadata_path.exists():
        pytest.skip("dataset-v1.2.0 is not built in this environment")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["hostTypeUsage"]["isModelFeature"] is False
