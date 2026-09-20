"""Phase 2.6 binary model, calibration and source-holdout tests."""

import json
from pathlib import Path

import numpy as np
import pytest

from src.evaluation.metrics import BINARY_LABEL_NAMES, calculate_binary_metrics
from src.models.lightgbm_binary import BINARY_LABEL_MAPPING, EXPERIMENT_ID, verify_binary_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
PHASE26_SUMMARY = REPO_ROOT / "reports" / "metrics" / "v1.3.0" / "phase26_summary.json"
URLBERT_BINARY_CONFIG = REPO_ROOT / "configs" / "urlbert_binary.yaml"


def test_binary_label_mapping_is_benign_zero_phishing_one():
    assert BINARY_LABEL_MAPPING == {"BENIGN": 0, "PHISHING": 1}
    assert BINARY_LABEL_NAMES == ["BENIGN", "PHISHING"]
    assert EXPERIMENT_ID == "LightGBM_PHISHING_BINARY_V1"


def test_binary_metrics_report_the_required_quantities():
    labels = np.array([0, 0, 1, 1, 1, 0])
    predicted = np.array([0, 1, 1, 1, 0, 0])
    probabilities = np.array(
        [[0.8, 0.2], [0.4, 0.6], [0.2, 0.8], [0.3, 0.7], [0.6, 0.4], [0.7, 0.3]]
    )
    metrics = calculate_binary_metrics(labels, predicted, probabilities)
    for key in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "specificity",
        "false_positive_rate",
        "false_negative_rate",
        "auroc",
        "auprc",
    ):
        assert key in metrics, key
    assert metrics["truePositive"] == 2
    assert metrics["falsePositive"] == 1
    assert metrics["falseNegative"] == 1
    assert metrics["trueNegative"] == 2
    assert metrics["specificity"] == pytest.approx(2 / 3)
    assert metrics["false_positive_rate"] == pytest.approx(1 / 3)


def test_binary_metrics_return_none_for_single_class_slices():
    labels = np.array([0, 0, 0])
    predicted = np.array([0, 0, 1])
    probabilities = np.array([[0.9, 0.1], [0.8, 0.2], [0.4, 0.6]])
    metrics = calculate_binary_metrics(labels, predicted, probabilities)
    assert metrics["auroc"] is None
    assert metrics["auprc"] is None
    assert metrics["precision"] == 0.0


def test_binary_manifest_guard_matches_the_sealed_test():
    if not (REPO_ROOT / "data" / "splits" / "v1.3.0" / "test_manifest_v1.3.0.json").exists():
        pytest.skip("dataset-v1.3.0 is not built in this environment")
    manifest = verify_binary_manifest()
    assert manifest["datasetVersion"] == "dataset-v1.3.0"


def test_binary_urlbert_config_uses_a_two_class_head():
    import yaml

    payload = yaml.safe_load(URLBERT_BINARY_CONFIG.read_text(encoding="utf-8"))["urlbert"]
    assert payload["label_mapping"] == {"BENIGN": 0, "PHISHING": 1}
    assert payload["dataset_version"] == "dataset-v1.3.0"
    assert payload["test_manifest_view"] == "binary"
    assert payload["training"]["early_stopping_metric"] == "phishing_f1"


def test_binary_urlbert_head_is_not_the_old_three_class_head():
    source = (REPO_ROOT / "src" / "models" / "urlbert" / "model.py").read_text(encoding="utf-8")
    assert "num_classes: int = NUM_CLASSES" in source
    assert "nn.Linear(hidden_size, num_classes)" in source
    train_source = (REPO_ROOT / "src" / "models" / "urlbert" / "train.py").read_text(encoding="utf-8")
    assert "num_classes=urlbert.num_classes" in train_source
    assert "urlbert.num_classes," in train_source


def test_calibration_fits_on_validation_and_applies_to_test_once():
    source = (REPO_ROOT / "src" / "evaluation" / "phase26.py").read_text(encoding="utf-8")
    assert 'loader("validation")' in source
    assert 'loader("test")' in source
    assert "fit_temperature(validation_probabilities, validation_labels)" in source
    fit_index = source.index("fit_temperature(validation_probabilities, validation_labels)")
    test_index = source.index("apply_temperature(test_probabilities, temperature)")
    assert fit_index < test_index
    assert '"fitSplit": "validation"' in source or 'fit_split="validation"' in source


def test_source_holdout_contract_removes_the_source_from_training_only():
    source = (REPO_ROOT / "src" / "evaluation" / "phase26.py").read_text(encoding="utf-8")
    assert "SOURCE_HOLDOUT_EXPERIMENTS" in source
    assert '"holdout_phishing_database"' in source
    assert '"holdout_openphish"' in source
    assert '"excludedSources": ("phishing_database",)' in source
    assert '"excludedSources": ("openphish",)' in source
    assert '"evaluationType": "external-source-holdout"' in source
    train_source = (REPO_ROOT / "src" / "models" / "lightgbm_binary.py").read_text(encoding="utf-8")
    assert 'train_frame["source"].astype(str).isin(excluded)' in train_source
    assert 'validation_frame["source"].astype(str).isin(excluded)' in train_source


def test_official_binary_results_are_recorded():
    if not PHASE26_SUMMARY.exists():
        pytest.skip("Phase 2.6 evaluation has not been run in this environment")
    summary = json.loads(PHASE26_SUMMARY.read_text(encoding="utf-8"))
    assert summary["task"] == "binary_phishing"
    assert set(summary["models"]) == {"lightgbm_binary", "urlbert_binary"}
    for name, payload in summary["models"].items():
        assert payload["calibration"]["fitSplit"] == "validation", name
        assert payload["calibration"]["fitRows"] > 0, name
        assert payload["testMetricsUncalibrated"]["auprc"] is not None, name
    assert set(summary["sourceHoldout"]) == {"holdout_phishing_database", "holdout_openphish"}


def test_official_threshold_tables_exist_for_both_models():
    for name in ("lightgbm_binary", "urlbert_binary"):
        path = REPO_ROOT / "reports" / "metrics" / "v1.3.0" / "calibration" / name / "threshold_tradeoff.csv"
        if not path.exists():
            pytest.skip("Phase 2.6 calibration has not been run in this environment")
        text = path.read_text(encoding="utf-8")
        for column in ("threshold", "precision", "recall", "fpr", "fnr"):
            assert column in text, (name, column)
        assert "validation" in text and "test" in text
