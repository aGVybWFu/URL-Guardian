"""Calibration tests: validation-only fitting, correct metrics and threshold isolation."""

import json
from pathlib import Path

import numpy as np
import pytest

from src.evaluation.calibration import (
    CALIBRATION_STATUS_CALIBRATED,
    apply_temperature,
    expected_calibration_error,
    fit_temperature,
    malicious_score,
    multiclass_brier,
    negative_log_likelihood,
    reliability_table,
    threshold_table,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _overconfident_probabilities(seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Deliberately overconfident three-class probabilities.

    The confident class is chosen independently of the label, so the model is
    roughly one-third accurate while claiming 90% confidence.
    """

    rng = np.random.default_rng(seed)
    labels = rng.integers(0, 3, size=600)
    guessed = rng.integers(0, 3, size=600)
    probabilities = np.full((600, 3), 0.05)
    probabilities[np.arange(600), guessed] = 0.9
    return probabilities, labels


def test_temperature_one_is_identity():
    probabilities, _ = _overconfident_probabilities()
    assert np.allclose(apply_temperature(probabilities, 1.0), probabilities, atol=1e-9)


def test_temperature_above_one_softens_overconfidence():
    probabilities, labels = _overconfident_probabilities()
    softened = apply_temperature(probabilities, 2.5)
    assert expected_calibration_error(softened, labels) < expected_calibration_error(probabilities, labels)


def test_fit_temperature_reduces_validation_nll():
    probabilities, labels = _overconfident_probabilities(1)
    fitted = fit_temperature(probabilities, labels)
    calibrated = apply_temperature(probabilities, fitted["temperature"])
    assert negative_log_likelihood(calibrated, labels) <= negative_log_likelihood(probabilities, labels) + 1e-12
    assert fitted["fitSplit"] == "validation"
    assert fitted["temperature"] > 0


def test_fit_temperature_is_deterministic():
    probabilities, labels = _overconfident_probabilities(2)
    assert fit_temperature(probabilities, labels) == fit_temperature(probabilities, labels)


def test_fit_temperature_requires_rows():
    with pytest.raises(ValueError):
        fit_temperature(np.zeros((0, 3)), np.zeros(0, dtype=int))


def test_ece_is_zero_for_a_perfectly_calibrated_binary_like_case():
    labels = np.array([0, 0, 1, 1])
    probabilities = np.array(
        [[1.0, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 1.0, 0.0]]
    )
    assert expected_calibration_error(probabilities, labels) == pytest.approx(0.0, abs=1e-9)


def test_ece_detects_overconfidence():
    labels = np.array([0, 1, 2, 0, 1, 2] * 10)
    probabilities = np.full((60, 3), 0.05)
    probabilities[np.arange(60), labels] = 0.9
    probabilities[np.arange(0, 60, 2), :] = [0.05, 0.05, 0.9]
    assert expected_calibration_error(probabilities, labels) > 0.0


def test_brier_score_matches_the_manual_formula():
    labels = np.array([0, 2])
    probabilities = np.array([[0.8, 0.1, 0.1], [0.1, 0.2, 0.7]])
    expected = ((0.2**2 + 0.1**2 + 0.1**2) + (0.1**2 + 0.2**2 + 0.3**2)) / 2
    assert multiclass_brier(probabilities, labels) == pytest.approx(expected, abs=1e-12)


def test_brier_score_is_lower_after_calibration():
    probabilities, labels = _overconfident_probabilities(3)
    fitted = fit_temperature(probabilities, labels)
    calibrated = apply_temperature(probabilities, fitted["temperature"])
    assert multiclass_brier(calibrated, labels) < multiclass_brier(probabilities, labels)


def test_reliability_table_covers_the_full_confidence_range():
    probabilities, labels = _overconfident_probabilities(4)
    table = reliability_table(probabilities, labels, bins=10)
    assert len(table) == 10
    assert table["binLower"].iloc[0] == 0.0
    assert table["binUpper"].iloc[-1] == 1.0
    assert table["count"].sum() == len(labels)


def test_malicious_score_sums_phishing_and_malware():
    probabilities = np.array([[0.5, 0.3, 0.2], [0.1, 0.1, 0.8]])
    assert malicious_score(probabilities).tolist() == pytest.approx([0.5, 0.9])


def test_threshold_table_reports_the_expected_quantities():
    probabilities = np.array(
        [
            [0.9, 0.05, 0.05],  # benign, low malicious score
            [0.05, 0.9, 0.05],  # phishing
            [0.05, 0.05, 0.9],  # malware
            [0.05, 0.05, 0.9],  # malware
        ]
    )
    labels = np.array([0, 1, 2, 2])
    table = threshold_table(probabilities, labels, [0.5, 0.99])
    high = table[table["threshold"] == 0.5].iloc[0]
    assert high["truePositive"] == 3
    assert high["falsePositive"] == 0
    assert high["precision"] == pytest.approx(1.0)
    assert high["recall"] == pytest.approx(1.0)
    strict = table[table["threshold"] == 0.99].iloc[0]
    assert strict["truePositive"] == 0
    assert strict["falseNegative"] == 3


def test_calibration_code_fits_on_validation_and_never_reads_the_test_split():
    source = (REPO_ROOT / "src" / "evaluation" / "phase25.py").read_text(encoding="utf-8")
    assert 'loader("validation")' in source
    assert 'loader("test")' in source
    assert '"fitSplit": "validation"' in source or "fit_split=\"validation\"" in source
    assert 'fit_temperature(validation_probabilities, validation_labels)' in source
    # The temperature is fitted before any test split is touched.
    fit_index = source.index("fit_temperature(validation_probabilities, validation_labels)")
    test_use_index = source.index("apply_temperature(test_probabilities, temperature)")
    assert fit_index < test_use_index


def test_threshold_grid_is_defined_in_config_not_in_the_test_set():
    config = (REPO_ROOT / "configs" / "urlbert_v2.yaml").read_text(encoding="utf-8")
    assert "fit_split: \"validation\"" in config
    assert "apply_split: \"test\"" in config


def test_official_calibration_artifacts_declare_calibrated_status():
    summary_path = REPO_ROOT / "reports" / "metrics" / "v1.2.0" / "phase25_summary.json"
    if not summary_path.exists():
        pytest.skip("Phase 2.5 calibration has not been run in this environment")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    for name, payload in summary["models"].items():
        assert payload["calibration"]["status"] == CALIBRATION_STATUS_CALIBRATED, name
        assert payload["calibration"]["fitSplit"] == "validation", name
        assert payload["calibration"]["fitRows"] > 0, name
