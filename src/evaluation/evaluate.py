from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.features.extractor import extract_feature_frame
from src.features.schema import FEATURE_NAMES
from src.models.train_lightgbm import LABEL_MAPPING
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger
from src.data.snapshot import sha256_file
from .metrics import LABEL_NAMES, calculate_metrics
from .plots import plot_confusion_matrix, plot_feature_importance

LOGGER = get_logger(__name__)


def _update_comparison(
    path: Path,
    view: str,
    metrics: dict[str, object],
    model_metadata: dict[str, object],
) -> None:
    row = {
        "Model": "LightGBM Domain Only" if view == "domain_only" else "LightGBM Full URL",
        "Dataset View": view.upper(),
        "Accuracy": metrics["accuracy"],
        "Macro Precision": metrics["macro_precision"],
        "Macro Recall": metrics["macro_recall"],
        "Macro F1": metrics["macro_f1"],
        "Weighted F1": metrics["weighted_f1"],
        "Phishing Recall": metrics["phishing_recall"],
        "Malware Recall": metrics["malware_recall"],
        "Benign FPR": metrics["benign_false_positive_rate"],
        "Malicious FNR": metrics["malicious_false_negative_rate"],
        "AUROC": metrics["auroc_ovr_macro"],
        "AUPRC": metrics["auprc_ovr_macro"],
        "Experiment Type": model_metadata["experimentType"],
        "Dataset Version": model_metadata["datasetVersion"],
        "Model Version": model_metadata["modelVersion"],
        "Model SHA-256": model_metadata["model_sha256"],
        "Test Manifest SHA-256": model_metadata.get("testManifestSha256"),
        "Test Set SHA-256": model_metadata.get("testSetSha256"),
    }
    frame = pd.read_csv(path) if path.exists() else pd.DataFrame()
    if not frame.empty:
        frame = frame[~((frame["Model"] == row["Model"]) & (frame["Dataset View"] == row["Dataset View"]))]
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([frame, pd.DataFrame([row])], ignore_index=True).to_csv(path, index=False)


def evaluate(config_path: str | Path | None = None, view: str | None = None) -> dict[str, object]:
    configure_logging()
    config = load_config(config_path)
    experiment_mode = str(config.get("training", {}).get("experiment_mode", "FIXTURE_VERIFICATION"))
    if experiment_mode == "OFFICIAL_EXPERIMENT" and view not in {"domain_only", "full_url"}:
        raise ValueError("Official evaluation requires an explicit dataset view")
    model_dir = project_path(config["paths"]["model_dir"])
    if view:
        model_dir = model_dir / view
    model_path = model_dir / "model.txt"
    metadata_path = model_dir / "metadata.json"
    if not model_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("Train the model before evaluation")
    split_dir = project_path(config["paths"]["splits"])
    if view:
        split_dir = split_dir / view
    test_path = split_dir / "test.csv"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if view:
        manifest_path = project_path(config["paths"]["splits"]) / "test_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        dataset_metadata = json.loads(project_path(config["paths"]["dataset_metadata"]).read_text(encoding="utf-8"))
        if experiment_mode == "OFFICIAL_EXPERIMENT" and not dataset_metadata.get("viewEligibility", {}).get(view, False):
            raise ValueError(f"Official {view} experiment is not eligible")
        if metadata.get("datasetVersion") != manifest.get("datasetVersion"):
            raise ValueError("Model and Test Manifest dataset versions do not match")
        if metadata.get("testManifestSha256") != sha256_file(manifest_path):
            raise ValueError("Model is not bound to the current Test Manifest")
        expected = manifest["views"][view]["sha256"]
        if sha256_file(test_path) != expected:
            raise ValueError("Sealed Test Set hash does not match test_manifest.json")
        if metadata.get("testSetSha256") != expected:
            raise ValueError("Model is not bound to the selected Test Set")
    test = pd.read_csv(test_path, dtype=str, low_memory=False)
    url_column = "model_url" if "model_url" in test else "normalized_url"
    features = extract_feature_frame(test[url_column])
    y_true = test["label"].map(LABEL_MAPPING).to_numpy()
    booster = lgb.Booster(model_str=model_path.read_text(encoding="utf-8"))
    probabilities = np.asarray(booster.predict(features[FEATURE_NAMES]))
    y_pred = probabilities.argmax(axis=1)
    metrics = calculate_metrics(y_true, y_pred, probabilities)

    metrics_dir = project_path(config["paths"]["metrics"])
    figures_dir = project_path(config["paths"]["figures"])
    if view:
        metrics_dir = metrics_dir / view
        figures_dir = figures_dir / view
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    (metrics_dir / "test_metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    plot_confusion_matrix(metrics["confusion_matrix"], LABEL_NAMES, figures_dir / "confusion_matrix.png")
    importance = pd.DataFrame(
        {"feature": FEATURE_NAMES, "importance": booster.feature_importance(importance_type="gain")}
    ).sort_values("importance", ascending=False)
    importance.to_csv(metrics_dir / "feature_importance.csv", index=False)
    top20 = importance.head(20).copy()
    top20.insert(0, "rank", range(1, len(top20) + 1))
    total_gain = float(importance["importance"].sum())
    top20["gain_fraction"] = top20["importance"] / total_gain if total_gain else 0.0
    top20.to_csv(metrics_dir / "feature_importance_top20.csv", index=False)
    plot_feature_importance(importance, figures_dir / "feature_importance.png")
    metadata.setdefault("metrics", {})["test"] = metrics
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    if view:
        _update_comparison(
            project_path(config["paths"]["metrics"]) / "baseline_comparison.csv", view, metrics, metadata
        )
    LOGGER.info("Test accuracy %.6f; macro F1 %.6f", metrics["accuracy"], metrics["macro_f1"])
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the trained baseline once on the test split")
    parser.add_argument("--config", default=None)
    parser.add_argument("--view", choices=["domain_only", "full_url"], default=None)
    parser.add_argument("--all", action="store_true", help="Evaluate both dataset views")
    args = parser.parse_args()
    try:
        if args.all:
            metrics = {view: evaluate(args.config, view) for view in ("domain_only", "full_url")}
        else:
            metrics = evaluate(args.config, args.view)
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
    except (FileNotFoundError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
