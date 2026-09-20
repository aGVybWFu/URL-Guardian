"""Probability calibration and threshold research.

Calibration is fitted on the Validation split only and then applied to the
sealed Test Set exactly once. Test data never influences the fitted
temperature, the bin edges or the threshold table.

Temperature scaling operates on log-probabilities, which is the natural
generalisation for models that expose probabilities rather than raw logits:

    calibrated = softmax(log(p) / T)

`T` is fitted by minimising validation negative log-likelihood.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

CALIBRATION_STATUS_CALIBRATED = "CALIBRATED_PROBABILITY"
CALIBRATION_STATUS_UNCALIBRATED = "UNCALIBRATED PROBABILITY"
EPSILON = 1e-12


def softmax(values: np.ndarray) -> np.ndarray:
    shifted = values - values.max(axis=1, keepdims=True)
    exponentiated = np.exp(shifted)
    return exponentiated / exponentiated.sum(axis=1, keepdims=True)


def log_probabilities(probabilities: np.ndarray) -> np.ndarray:
    return np.log(np.clip(probabilities, EPSILON, 1.0))


def apply_temperature(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    """Return softmax(log(p) / T), which reduces to p when T = 1."""

    if temperature <= 0:
        raise ValueError("Temperature must be positive")
    return softmax(log_probabilities(probabilities) / float(temperature))


def negative_log_likelihood(probabilities: np.ndarray, labels: np.ndarray) -> float:
    picked = probabilities[np.arange(len(labels)), labels]
    return float(-np.mean(np.log(np.clip(picked, EPSILON, 1.0))))


def multiclass_brier(probabilities: np.ndarray, labels: np.ndarray, num_classes: int = 3) -> float:
    """Mean squared error between the probability vector and the one-hot label."""

    one_hot = np.zeros_like(probabilities)
    one_hot[np.arange(len(labels)), labels] = 1.0
    return float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))


def expected_calibration_error(
    probabilities: np.ndarray, labels: np.ndarray, bins: int = 15
) -> float:
    """Equal-width ECE on the predicted-class confidence."""

    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == labels).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(labels)
    if total == 0:
        return 0.0
    error = 0.0
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        mask = (confidence > lower) & (confidence <= upper) if index else (confidence >= lower) & (confidence <= upper)
        if not mask.any():
            continue
        bin_confidence = float(confidence[mask].mean())
        bin_accuracy = float(correct[mask].mean())
        error += (mask.sum() / total) * abs(bin_accuracy - bin_confidence)
    return float(error)


def reliability_table(
    probabilities: np.ndarray, labels: np.ndarray, bins: int = 15
) -> pd.DataFrame:
    """Per-bin confidence, accuracy and counts for the reliability diagram."""

    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == labels).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows: list[dict[str, Any]] = []
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        mask = (confidence > lower) & (confidence <= upper) if index else (confidence >= lower) & (confidence <= upper)
        rows.append(
            {
                "binIndex": index,
                "binLower": float(lower),
                "binUpper": float(upper),
                "count": int(mask.sum()),
                "meanConfidence": float(confidence[mask].mean()) if mask.any() else None,
                "accuracy": float(correct[mask].mean()) if mask.any() else None,
            }
        )
    return pd.DataFrame(rows)


def fit_temperature(
    probabilities: np.ndarray,
    labels: np.ndarray,
    candidates: Iterable[float] | None = None,
) -> dict[str, Any]:
    """Fit the temperature that minimises validation NLL.

    A dense deterministic grid is used instead of a gradient optimiser so that
    the fitted value is exactly reproducible.
    """

    if len(labels) == 0:
        raise ValueError("Cannot fit a temperature without validation rows")
    grid = (
        list(candidates)
        if candidates is not None
        else [round(0.05 * step, 2) for step in range(1, 101)] + [round(0.25 * step, 2) for step in range(21, 61)]
    )
    scored: list[tuple[float, float]] = []
    for temperature in sorted(set(float(value) for value in grid)):
        if temperature <= 0:
            continue
        scaled = apply_temperature(probabilities, temperature)
        scored.append((negative_log_likelihood(scaled, labels), temperature))
    best_nll, best_temperature = min(scored, key=lambda item: (item[0], item[1]))
    return {
        "temperature": float(best_temperature),
        "validationNll": float(best_nll),
        "gridSize": len(scored),
        "method": "temperature_scaling_on_log_probabilities",
        "fitSplit": "validation",
    }


def malicious_score(probabilities: np.ndarray) -> np.ndarray:
    """Malicious score used for the ALLOW / REVIEW / BLOCK research."""

    return probabilities[:, 1] + probabilities[:, 2]


def threshold_table(
    probabilities: np.ndarray,
    labels: np.ndarray,
    thresholds: Sequence[float],
) -> pd.DataFrame:
    """TPR / FPR / precision / recall trade-off table for the malicious score."""

    score = malicious_score(probabilities)
    malicious_true = labels != 0
    benign_true = labels == 0
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        flagged = score >= float(threshold)
        true_positive = int((flagged & malicious_true).sum())
        false_positive = int((flagged & benign_true).sum())
        false_negative = int((~flagged & malicious_true).sum())
        true_negative = int((~flagged & benign_true).sum())
        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0
        fpr = false_positive / (false_positive + true_negative) if (false_positive + true_negative) else 0.0
        rows.append(
            {
                "threshold": float(threshold),
                "truePositive": true_positive,
                "falsePositive": false_positive,
                "falseNegative": false_negative,
                "trueNegative": true_negative,
                "tpr": recall,
                "fpr": fpr,
                "precision": precision,
                "recall": recall,
                "flaggedShare": float(flagged.mean()) if len(flagged) else 0.0,
            }
        )
    return pd.DataFrame(rows)


@dataclass(frozen=True)
class CalibrationBundle:
    """Fitted calibration plus the split contract that produced it."""

    temperature: float
    fit_split: str
    fit_rows: int
    method: str
    validation_nll: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "temperature": self.temperature,
            "fitSplit": self.fit_split,
            "fitRows": self.fit_rows,
            "validationNll": self.validation_nll,
            "appliedTo": "sealed test set, once",
            "status": CALIBRATION_STATUS_CALIBRATED,
        }


def summarise(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    bins: int = 15,
) -> dict[str, float]:
    return {
        "negativeLogLikelihood": negative_log_likelihood(probabilities, labels),
        "brierScore": multiclass_brier(probabilities, labels),
        "expectedCalibrationError": expected_calibration_error(probabilities, labels, bins),
    }


def write_calibration_outputs(
    output_dir: str | Path,
    *,
    split: str,
    uncalibrated: np.ndarray,
    calibrated: np.ndarray,
    labels: np.ndarray,
    bundle: CalibrationBundle,
    bins: int = 15,
) -> dict[str, Any]:
    """Persist reliability tables and the calibration summary for one split."""

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    reliability_table(uncalibrated, labels, bins).to_csv(
        directory / f"{split}_reliability_uncalibrated.csv", index=False
    )
    reliability_table(calibrated, labels, bins).to_csv(
        directory / f"{split}_reliability_calibrated.csv", index=False
    )
    summary = {
        "split": split,
        "uncalibrated": summarise(uncalibrated, labels, bins=bins),
        "calibrated": summarise(calibrated, labels, bins=bins),
        "calibration": bundle.to_dict(),
    }
    (directory / f"{split}_calibration_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary
