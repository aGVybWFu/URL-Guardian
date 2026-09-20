"""Phase 2.6 binary evaluation: calibration, thresholds and source holdout.

All decisions use the Validation split. The frozen binary Test Set is read once,
after the calibration method and the threshold grid are already fixed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch

from src.data.snapshot import sha256_file
from src.evaluation.calibration import (
    CalibrationBundle,
    apply_temperature,
    fit_temperature,
    reliability_table,
    summarise,
)
from src.evaluation.metrics import BINARY_LABEL_NAMES, calculate_binary_metrics
from src.features.extractor import extract_feature_frame
from src.models.lightgbm_binary import (
    BINARY_LABEL_MAPPING,
    EXPERIMENT_ID,
    SPLITS_ROOT,
    MANIFEST_PATH,
    _load_split,
    _labels,
    verify_binary_manifest,
)
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
METRICS_ROOT = Path("reports/metrics/v1.3.0")
SOURCE_HOLDOUT_EXPERIMENTS = {
    "holdout_phishing_database": {
        "excludedSources": ("phishing_database",),
        "trainSources": ("cert_polska", "openphish"),
    },
    "holdout_openphish": {
        "excludedSources": ("openphish",),
        "trainSources": ("cert_polska", "phishing_database"),
    },
}


def lightgbm_probabilities(experiment: str, split: str) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    model_dir = project_path("models/lightgbm_binary") / experiment
    model_path = model_dir / "model.txt"
    metadata_path = model_dir / "metadata.json"
    if not model_path.exists() or not metadata_path.exists():
        raise FileNotFoundError(f"Train the {experiment} binary model first")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    features = list(metadata["featureNames"])
    booster = lgb.Booster(model_str=model_path.read_text(encoding="utf-8"))
    frame = _load_split(split)
    x = extract_feature_frame(frame["model_url"])[features]
    raw = np.asarray(booster.predict(x))
    if raw.ndim == 1:
        # A LightGBM binary booster returns the positive-class probability only.
        probabilities = np.column_stack([1.0 - raw, raw])
    else:
        probabilities = raw
    return probabilities, _labels(frame), frame


def urlbert_probabilities(config_path: str | Path, split: str) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    from transformers import AutoTokenizer

    from src.models.urlbert.config import load_urlbert_config
    from src.models.urlbert.dataset import tokenize_frame
    from src.models.urlbert.model import load_checkpoint

    config = load_urlbert_config(config_path)
    best_path = config.path("checkpoint_dir") / "best.pt"
    if not best_path.exists():
        raise FileNotFoundError("Train the URLBERT binary checkpoint first")
    tokenizer = AutoTokenizer.from_pretrained(config.base_model, revision=config.base_model_revision)
    model, _ = load_checkpoint(best_path, config.base_model, config.base_model_revision)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    frame = _load_split(split)
    tokenized = tokenize_frame(frame, split, config, tokenizer)
    outputs: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(tokenized), 256):
            stop = start + 256
            logits = model(
                tokenized.input_ids[start:stop].to(device),
                tokenized.attention_mask[start:stop].to(device),
            )
            outputs.append(torch.softmax(logits.float(), dim=-1).cpu().numpy())
    return np.concatenate(outputs, axis=0), _labels(frame), frame


def binary_threshold_table(
    probabilities: np.ndarray,
    labels: np.ndarray,
    thresholds: list[float],
) -> pd.DataFrame:
    """Threshold trade-off for the phishing score (P(PHISHING))."""

    score = probabilities[:, 1]
    phishing = labels == 1
    benign = labels == 0
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        flagged = score >= float(threshold)
        true_positive = int((flagged & phishing).sum())
        false_positive = int((flagged & benign).sum())
        false_negative = int((~flagged & phishing).sum())
        true_negative = int((~flagged & benign).sum())
        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0
        fpr = false_positive / (false_positive + true_negative) if (false_positive + true_negative) else 0.0
        fnr = false_negative / (false_negative + true_positive) if (false_negative + true_positive) else 0.0
        rows.append(
            {
                "threshold": float(threshold),
                "truePositive": true_positive,
                "falsePositive": false_positive,
                "falseNegative": false_negative,
                "trueNegative": true_negative,
                "precision": precision,
                "recall": recall,
                "fpr": fpr,
                "fnr": fnr,
                "flaggedShare": float(flagged.mean()) if len(flagged) else 0.0,
            }
        )
    return pd.DataFrame(rows)


def _reliability_plot(table: pd.DataFrame, path: Path, title: str) -> None:
    subset = table.dropna(subset=["meanConfidence", "accuracy"])
    figure, axis = plt.subplots(figsize=(5, 5))
    axis.plot([0, 1], [0, 1], linestyle="--", color="grey", label="Perfect calibration")
    if not subset.empty:
        axis.plot(subset["meanConfidence"], subset["accuracy"], marker="o", label="Observed")
    axis.set(title=title, xlabel="Mean predicted confidence", ylabel="Empirical accuracy")
    axis.legend(loc="best")
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=160)
    plt.close(figure)


def calibrate_binary_model(
    name: str,
    validation: tuple[np.ndarray, np.ndarray, pd.DataFrame],
    test: tuple[np.ndarray, np.ndarray, pd.DataFrame],
    output_dir: Path,
    thresholds: list[float],
    bins: int = 15,
) -> dict[str, Any]:
    validation_probabilities, validation_labels, _ = validation
    test_probabilities, test_labels, _ = test
    fitted = fit_temperature(validation_probabilities, validation_labels)
    bundle = CalibrationBundle(
        temperature=float(fitted["temperature"]),
        fit_split="validation",
        fit_rows=int(len(validation_labels)),
        method=str(fitted["method"]),
        validation_nll=float(fitted["validationNll"]),
    )
    temperature = bundle.temperature
    directory = output_dir / name
    directory.mkdir(parents=True, exist_ok=True)
    validation_calibrated = apply_temperature(validation_probabilities, temperature)
    test_calibrated = apply_temperature(test_probabilities, temperature)

    summary = {
        "model": name,
        "task": "binary_phishing",
        "validation": summarise(validation_probabilities, validation_labels, bins=bins),
        "validationCalibrated": summarise(validation_calibrated, validation_labels, bins=bins),
        "test": summarise(test_probabilities, test_labels, bins=bins),
        "testCalibrated": summarise(test_calibrated, test_labels, bins=bins),
        "testMetricsUncalibrated": calculate_binary_metrics(
            test_labels, test_probabilities.argmax(axis=1), test_probabilities
        ),
        "testMetricsCalibrated": calculate_binary_metrics(
            test_labels, test_calibrated.argmax(axis=1), test_calibrated
        ),
        "calibration": {
            **bundle.to_dict(),
            "modelVersion": "0.6.0",
            "datasetVersion": "dataset-v1.3.0",
            "testManifestSHA256": sha256_file(project_path(MANIFEST_PATH)),
        },
        "labelNames": BINARY_LABEL_NAMES,
    }
    for split, uncalibrated, calibrated, labels in (
        ("validation", validation_probabilities, validation_calibrated, validation_labels),
        ("test", test_probabilities, test_calibrated, test_labels),
    ):
        reliability_table(uncalibrated, labels, bins).to_csv(
            directory / f"{split}_reliability_uncalibrated.csv", index=False
        )
        reliability_table(calibrated, labels, bins).to_csv(
            directory / f"{split}_reliability_calibrated.csv", index=False
        )
    _reliability_plot(
        reliability_table(test_probabilities, test_labels, bins),
        directory / "reliability_test_uncalibrated.png",
        f"{name} test reliability (uncalibrated)",
    )
    _reliability_plot(
        reliability_table(test_calibrated, test_labels, bins),
        directory / "reliability_test_calibrated.png",
        f"{name} test reliability (calibrated, T={temperature:.3f})",
    )

    validation_thresholds = binary_threshold_table(validation_calibrated, validation_labels, thresholds)
    validation_thresholds.insert(0, "split", "validation")
    test_thresholds = binary_threshold_table(test_calibrated, test_labels, thresholds)
    test_thresholds.insert(0, "split", "test")
    pd.concat([validation_thresholds, test_thresholds], ignore_index=True).to_csv(
        directory / "threshold_tradeoff.csv", index=False
    )
    summary["thresholds"] = {
        "definition": "phishing score = P(PHISHING), calibrated",
        "fitSplit": "validation",
        "grid": thresholds,
        "note": (
            "No threshold is declared optimal. Choosing one requires an explicit cost function, "
            "which is out of scope for this phase."
        ),
    }
    (directory / "calibration_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def source_holdout(experiment: str, config_path: str | Path | None = None) -> dict[str, Any]:
    """Train without one phishing source and evaluate on its frozen Test rows."""

    if experiment not in SOURCE_HOLDOUT_EXPERIMENTS:
        raise ValueError(f"Unknown source-holdout experiment: {experiment}")
    specification = SOURCE_HOLDOUT_EXPERIMENTS[experiment]
    from src.models.lightgbm_binary import train_experiment

    experiment_id = f"{EXPERIMENT_ID}_SOURCE_HOLDOUT_{experiment.removeprefix('holdout_').upper()}"
    # The holdout experiment retrains a LightGBM model, so it uses the LightGBM
    # configuration, never the URLBERT configuration.
    metrics = train_experiment(
        None,
        exclude_sources=tuple(specification["excludedSources"]),
        experiment_id=experiment_id,
        output_suffix=experiment,
    )
    held_out = specification["excludedSources"][0]
    test_frame = _load_split("test")
    held_out_mask = test_frame["source"].astype(str).eq(held_out).to_numpy()
    payload = {
        "experiment": experiment,
        "experimentId": experiment_id,
        "heldOutSource": held_out,
        "trainSources": list(specification["trainSources"]),
        "excludedSources": list(specification["excludedSources"]),
        "evaluationType": "external-source-holdout",
        "evaluationNote": (
            "The held-out source never appeared in Train or Validation. Its frozen Test rows are "
            "therefore an external-source evaluation, not a subgroup of a seen source."
        ),
        "heldOutSourceRows": int(held_out_mask.sum()),
        "heldOutSourceMetrics": metrics["sourceSubgroups"].get(held_out),
        "seenSourcesMetrics": {
            source: values
            for source, values in metrics["sourceSubgroups"].items()
            if source != held_out
        },
        "allTestMetrics": {
            key: metrics[key]
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
            )
        },
        "testSetSHA256": metrics["testSetSHA256"],
    }
    output_dir = METRICS_ROOT / "source_holdout"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{experiment}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return payload


def run(config_path: str | Path = "configs/urlbert_binary.yaml") -> dict[str, Any]:
    configure_logging()
    from src.models.urlbert.config import load_urlbert_config

    config = load_urlbert_config(config_path)
    thresholds = [float(value) for value in config.raw.get("thresholds", {}).get("grid", [0.5])]
    verify_binary_manifest()
    output_dir = METRICS_ROOT / "calibration"

    results: dict[str, Any] = {"task": "binary_phishing", "models": {}, "sourceHoldout": {}}
    for name, loader in (
        ("lightgbm_binary", lambda split: lightgbm_probabilities("v1", split)),
        ("urlbert_binary", lambda split: urlbert_probabilities(config_path, split)),
    ):
        LOGGER.info("Calibrating %s", name)
        results["models"][name] = calibrate_binary_model(
            name, loader("validation"), loader("test"), output_dir, thresholds
        )

    for experiment in SOURCE_HOLDOUT_EXPERIMENTS:
        LOGGER.info("Running source-holdout experiment %s", experiment)
        results["sourceHoldout"][experiment] = source_holdout(experiment, config_path)

    (METRICS_ROOT / "phase26_summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run Phase 2.6 binary calibration, thresholds and source holdout")
    parser.add_argument("--config", default="configs/urlbert_binary.yaml")
    args = parser.parse_args()
    try:
        result = run(args.config)
        for name, payload in result["models"].items():
            print(
                f"{name}: T={payload['calibration']['temperature']:.3f} "
                f"ECE {payload['test']['expectedCalibrationError']:.4f} -> "
                f"{payload['testCalibrated']['expectedCalibrationError']:.4f} | "
                f"Brier {payload['test']['brierScore']:.4f} -> "
                f"{payload['testCalibrated']['brierScore']:.4f}"
            )
        for experiment, payload in result["sourceHoldout"].items():
            held = payload["heldOutSourceMetrics"] or {}
            print(
                f"{experiment}: held-out rows={payload['heldOutSourceRows']} "
                f"recall={held.get('recall')} f1={held.get('f1')}"
            )
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
