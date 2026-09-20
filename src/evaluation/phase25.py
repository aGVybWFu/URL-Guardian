"""Phase 2.5 evaluation pipeline: calibration, threshold research and source holdout.

Everything here respects one rule: the sealed Test Set is read once, after every
decision has already been made on the Validation split.
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
    expected_calibration_error,
    fit_temperature,
    malicious_score,
    multiclass_brier,
    negative_log_likelihood,
    reliability_table,
    summarise,
    threshold_table,
    write_calibration_outputs,
)
from src.evaluation.metrics import LABEL_NAMES
from src.features.extractor import extract_feature_frame
from src.models.train_lightgbm import LABEL_MAPPING
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
SPLITS_ROOT = Path("data/splits/v1.2.0")
METRICS_ROOT = Path("reports/metrics/v1.2.0")
FIGURES_ROOT = Path("reports/figures/v1.2.0")


def _load_split(regime: str, split: str) -> pd.DataFrame:
    path = SPLITS_ROOT / regime / f"{split}.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing frozen split: {path}")
    return pd.read_csv(path, dtype=str, low_memory=False)


def _labels(frame: pd.DataFrame) -> np.ndarray:
    return frame["label"].map(LABEL_MAPPING).to_numpy(dtype=int)


def lightgbm_probabilities(
    regime: str, experiment: str, split: str
) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """Load a trained LightGBM V2 model and score one frozen split."""

    model_dir = Path("models/lightgbm_v2") / f"{regime}_{experiment}"
    model_path = model_dir / "model.txt"
    metadata_path = model_dir / "metadata.json"
    if not model_path.exists() or not metadata_path.exists():
        raise FileNotFoundError(f"Train the {regime}/{experiment} LightGBM model first")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    features = list(metadata["featureNames"])
    booster = lgb.Booster(model_str=model_path.read_text(encoding="utf-8"))
    frame = _load_split(regime, split)
    x = extract_feature_frame(frame["model_url"])[features]
    return np.asarray(booster.predict(x)), _labels(frame), frame


def urlbert_probabilities(
    config_path: str | Path, split: str
) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """Load the trained URLBERT V2 checkpoint and score one frozen split."""

    from transformers import AutoTokenizer

    from src.models.urlbert.config import load_urlbert_config
    from src.models.urlbert.dataset import tokenize_frame
    from src.models.urlbert.model import load_checkpoint

    config = load_urlbert_config(config_path)
    checkpoint_dir = config.path("checkpoint_dir")
    best_path = checkpoint_dir / "best.pt"
    if not best_path.exists():
        raise FileNotFoundError("Train the URLBERT V2 checkpoint first")
    tokenizer = AutoTokenizer.from_pretrained(config.base_model, revision=config.base_model_revision)
    model, _ = load_checkpoint(best_path, config.base_model, config.base_model_revision)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    frame = _load_split(config.manifest_view, split)
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


def calibrate_model(
    name: str,
    validation: tuple[np.ndarray, np.ndarray, pd.DataFrame],
    test: tuple[np.ndarray, np.ndarray, pd.DataFrame],
    output_dir: Path,
    thresholds: list[float],
    bins: int = 15,
) -> dict[str, Any]:
    """Fit temperature scaling on Validation and apply it once to Test."""

    validation_probabilities, validation_labels, _ = validation
    test_probabilities, test_labels, test_frame = test
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
        "validation": summarise(validation_probabilities, validation_labels, bins=bins),
        "validationCalibrated": summarise(validation_calibrated, validation_labels, bins=bins),
        "test": summarise(test_probabilities, test_labels, bins=bins),
        "testCalibrated": summarise(test_calibrated, test_labels, bins=bins),
        "calibration": bundle.to_dict(),
        "testSetSHA256": sha256_file(SPLITS_ROOT / "test_manifest_v1.2.0.json"),
    }
    write_calibration_outputs(
        directory,
        split="validation",
        uncalibrated=validation_probabilities,
        calibrated=validation_calibrated,
        labels=validation_labels,
        bundle=bundle,
        bins=bins,
    )
    write_calibration_outputs(
        directory,
        split="test",
        uncalibrated=test_probabilities,
        calibrated=test_calibrated,
        labels=test_labels,
        bundle=bundle,
        bins=bins,
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

    validation_thresholds = threshold_table(validation_calibrated, validation_labels, thresholds)
    validation_thresholds.insert(0, "split", "validation")
    test_thresholds = threshold_table(test_calibrated, test_labels, thresholds)
    test_thresholds.insert(0, "split", "test")
    combined = pd.concat([validation_thresholds, test_thresholds], ignore_index=True)
    combined.to_csv(directory / "threshold_tradeoff.csv", index=False)

    summary["thresholds"] = {
        "definition": "malicious score = P(PHISHING) + P(MALWARE), calibrated",
        "fitSplit": "validation",
        "grid": thresholds,
        "testSetRowsReportedForTheSameFixedThresholds": int(len(test_labels)),
        "note": (
            "No threshold is declared optimal. Selecting one requires an explicit cost function, "
            "which is out of scope for this phase."
        ),
    }
    (directory / "calibration_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def _subgroup_recall(frame: pd.DataFrame, probabilities: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    predicted = probabilities.argmax(axis=1)
    output: dict[str, Any] = {}
    for name, mask in (
        ("ip_host", frame["host_type"].astype(str).to_numpy() != "DOMAIN"),
        ("non_ip_host", frame["host_type"].astype(str).to_numpy() == "DOMAIN"),
    ):
        malware = mask & (labels == 2)
        output[name] = {
            "rows": int(mask.sum()),
            "malwareSupport": int(malware.sum()),
            "malwareRecall": float((predicted[malware] == 2).mean()) if malware.any() else None,
        }
    return output


def source_holdout_lightgbm(
    regime: str,
    held_out_source: str,
    output_dir: Path,
    config_path: str | Path | None = None,
    thresholds: list[float] | None = None,
) -> dict[str, Any]:
    """Train without one source and evaluate on that source's frozen Test rows.

    The frozen splits are reused unchanged: only the held-out source's rows are
    removed from Train and Validation. The Test Set is untouched, so the held-out
    source's Test rows form a genuine external-source evaluation.
    """

    from src.utils.config import load_config

    # The source-holdout experiment retrains a LightGBM model, so it uses the
    # LightGBM configuration, never the URLBERT configuration.
    config = load_config(None)
    train = _load_split(regime, "train")
    validation = _load_split(regime, "validation")
    test = _load_split(regime, "test")
    train_holdout = train[train["source"].astype(str) != held_out_source]
    validation_holdout = validation[validation["source"].astype(str) != held_out_source]
    if train_holdout.empty or validation_holdout.empty:
        raise ValueError(f"Holding out {held_out_source} leaves no training data")

    features = list(
        json.loads(
            (Path("models/lightgbm_v2") / f"{regime}_full" / "metadata.json").read_text(encoding="utf-8")
        )["featureNames"]
    )
    parameters = dict(config["training"]["parameters"])
    model = lgb.LGBMClassifier(
        **parameters,
        class_weight="balanced" if bool(config["training"]["use_class_weight"]) else None,
        verbosity=-1,
    )
    model.fit(
        extract_feature_frame(train_holdout["model_url"])[features],
        train_holdout["label"].map(LABEL_MAPPING),
        eval_X=extract_feature_frame(validation_holdout["model_url"])[features],
        eval_y=validation_holdout["label"].map(LABEL_MAPPING),
        eval_metric="multi_logloss",
    )

    test_probabilities = np.asarray(model.predict_proba(extract_feature_frame(test["model_url"])[features]))
    test_labels = _labels(test)
    held_out_mask = test["source"].astype(str) == held_out_source
    seen_mask = ~held_out_mask
    from src.evaluation.metrics import calculate_metrics

    def metrics_for(mask: np.ndarray) -> dict[str, Any]:
        if not mask.any():
            return {"rows": 0}
        metrics = calculate_metrics(test_labels[mask], test_probabilities[mask].argmax(axis=1), test_probabilities[mask])
        return {
            "rows": int(mask.sum()),
            "accuracy": metrics["accuracy"],
            "macroF1": metrics["macro_f1"],
            "macroPrecision": metrics["macro_precision"],
            "macroRecall": metrics["macro_recall"],
            "malwareRecall": metrics["malware_recall"],
            "phishingRecall": metrics["phishing_recall"],
            "benignFpr": metrics["benign_false_positive_rate"],
        }

    payload = {
        "model": f"LightGBM_DOMAIN_ONLY_V2_SOURCE_HOLDOUT_{held_out_source}",
        "regime": regime,
        "heldOutSource": held_out_source,
        "trainRowsAfterHoldout": int(len(train_holdout)),
        "validationRowsAfterHoldout": int(len(validation_holdout)),
        "heldOutTrainRowsRemoved": int(len(train) - len(train_holdout)),
        "heldOutValidationRowsRemoved": int(len(validation) - len(validation_holdout)),
        "evaluationType": "external-source-holdout",
        "evaluationNote": (
            "The held-out source never appeared in Train or Validation. Its frozen Test rows are "
            "therefore an external-source evaluation, not a subgroup of a seen source."
        ),
        "heldOutSourceMetrics": metrics_for(held_out_mask.to_numpy()),
        "seenSourcesMetrics": metrics_for(seen_mask.to_numpy()),
        "allTestMetrics": metrics_for(np.ones(len(test), dtype=bool)),
        "subgroups": _subgroup_recall(test, test_probabilities, test_labels),
        "testSetSHA256": json.loads(
            (SPLITS_ROOT / "test_manifest_v1.2.0.json").read_text(encoding="utf-8")
        )["views"][regime]["sha256"],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"source_holdout_{held_out_source}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return payload


def run(config_path: str | Path | None = None, regime: str = "artifact_controlled") -> dict[str, Any]:
    """Run calibration, thresholds and the source-holdout experiment."""

    configure_logging()
    from src.models.urlbert.config import load_urlbert_config

    urlbert_config = load_urlbert_config(config_path)
    thresholds = [float(value) for value in urlbert_config.raw.get("thresholds", {}).get("grid", [0.5])]
    bins = 15
    output_dir = METRICS_ROOT / "calibration"

    results: dict[str, Any] = {"regime": regime, "models": {}}
    for name, loader in (
        ("lightgbm_v2_full", lambda split: lightgbm_probabilities(regime, "full", split)),
        ("lightgbm_v2_no_ip", lambda split: lightgbm_probabilities(regime, "no_ip", split)),
        ("urlbert_v2", lambda split: urlbert_probabilities(config_path, split)),
    ):
        LOGGER.info("Calibrating %s", name)
        results["models"][name] = calibrate_model(
            name,
            loader("validation"),
            loader("test"),
            output_dir,
            thresholds,
            bins,
        )

    holdout_dir = METRICS_ROOT / "source_holdout"
    results["sourceHoldout"] = {}
    for held_out in ("threatfox",):
        LOGGER.info("Running source-holdout experiment for %s", held_out)
        results["sourceHoldout"][held_out] = source_holdout_lightgbm(
            regime, held_out, holdout_dir, config_path, thresholds
        )

    (METRICS_ROOT / "phase25_summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run Phase 2.5 calibration, thresholds and source holdout")
    parser.add_argument("--config", default="configs/urlbert_v2.yaml")
    parser.add_argument("--regime", default="artifact_controlled")
    args = parser.parse_args()
    try:
        result = run(args.config, args.regime)
        for name, payload in result["models"].items():
            print(
                f"{name}: T={payload['calibration']['temperature']:.3f} "
                f"ECE {payload['test']['expectedCalibrationError']:.4f} -> "
                f"{payload['testCalibrated']['expectedCalibrationError']:.4f} | "
                f"Brier {payload['test']['brierScore']:.4f} -> "
                f"{payload['testCalibrated']['brierScore']:.4f}"
            )
        holdout = result["sourceHoldout"]["threatfox"]
        print(
            "source-holdout threatfox: rows="
            f"{holdout['heldOutSourceMetrics']['rows']} "
            f"malwareRecall={holdout['heldOutSourceMetrics']['malwareRecall']}"
        )
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
