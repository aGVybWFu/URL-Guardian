"""Phase 2.6 binary phishing models on dataset-v1.3.0.

Two model families share the same frozen binary splits:

* `LightGBM_PHISHING_BINARY_V1` (this module)
* `URLBERT_PHISHING_BINARY_V1` (see `configs/urlbert_binary.yaml`)

Both report phishing precision/recall/F1, specificity, benign FPR, FNR, AUROC and
AUPRC. The Test Set is only read after the model is fully trained.
"""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn

from src.data.snapshot import sha256_file
from src.evaluation.metrics import BINARY_LABEL_NAMES, calculate_binary_metrics
from src.evaluation.plots import plot_confusion_matrix
from src.features.extractor import extract_feature_frame
from src.features.schema import FEATURE_NAMES, SCHEMA_VERSION, write_feature_schema
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
SPLITS_ROOT = Path("data/splits/v1.3.0/binary")
MANIFEST_PATH = Path("data/splits/v1.3.0/test_manifest_v1.3.0.json")
BINARY_LABEL_MAPPING = {"BENIGN": 0, "PHISHING": 1}
EXPERIMENT_ID = "LightGBM_PHISHING_BINARY_V1"


def _load_split(split: str) -> pd.DataFrame:
    path = project_path(SPLITS_ROOT / f"{split}.csv")
    if not path.exists():
        raise FileNotFoundError("Build dataset-v1.3.0 before training")
    return pd.read_csv(path, dtype=str, low_memory=False)


def _labels(frame: pd.DataFrame) -> np.ndarray:
    return frame["label"].map(BINARY_LABEL_MAPPING).to_numpy(dtype=int)


def verify_binary_manifest() -> dict[str, Any]:
    """Verify the sealed binary Test Set before any training or evaluation."""

    path = project_path(MANIFEST_PATH)
    if not path.exists():
        raise FileNotFoundError("Binary Test Manifest is missing")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("datasetVersion") != "dataset-v1.3.0":
        raise RuntimeError("Binary Test Manifest does not belong to dataset-v1.3.0")
    entry = manifest["views"]["binary"]
    test_path = project_path(SPLITS_ROOT / "test.csv")
    if sha256_file(test_path) != entry["sha256"]:
        raise RuntimeError("Sealed binary Test Set does not match the manifest")
    return manifest


def _subgroup_metrics(frame: pd.DataFrame, labels: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    predicted = probabilities.argmax(axis=1)
    output: dict[str, Any] = {}
    for name, mask in (
        ("ip_host", frame["host_type"].astype(str).to_numpy() != "DOMAIN")
        if "host_type" in frame.columns
        else ("ip_host", np.zeros(len(frame), dtype=bool)),
        ("non_ip_host", frame["host_type"].astype(str).to_numpy() == "DOMAIN")
        if "host_type" in frame.columns
        else ("non_ip_host", np.ones(len(frame), dtype=bool)),
    ):
        if not mask.any():
            output[name] = {"rows": 0}
            continue
        metrics = calculate_binary_metrics(labels[mask], predicted[mask], probabilities[mask])
        output[name] = {
            "rows": int(mask.sum()),
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "benignFpr": metrics["false_positive_rate"],
            "auroc": metrics["auroc"],
            "auprc": metrics["auprc"],
        }
    return output


def _source_subgroups(frame: pd.DataFrame, labels: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    predicted = probabilities.argmax(axis=1)
    output: dict[str, Any] = {}
    for source, group in frame.groupby("source", sort=True):
        mask = frame["source"].astype(str).eq(str(source)).to_numpy()
        metrics = calculate_binary_metrics(labels[mask], predicted[mask], probabilities[mask])
        output[str(source)] = {
            "rows": int(mask.sum()),
            "labelDistribution": {
                str(key): int(value) for key, value in group["label"].value_counts().sort_index().items()
            },
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "benignFpr": metrics["false_positive_rate"],
        }
    return output


def _update_comparison(path: Path, row: dict[str, object]) -> None:
    frame = pd.read_csv(path) if path.exists() else pd.DataFrame()
    if not frame.empty and {"Model", "Dataset Version"} <= set(frame.columns):
        frame = frame[~((frame["Model"] == row["Model"]) & (frame["Dataset Version"] == row["Dataset Version"]))]
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([frame, pd.DataFrame([row])], ignore_index=True).to_csv(path, index=False)


def train_experiment(
    config_path: str | Path | None = None,
    *,
    exclude_sources: tuple[str, ...] = (),
    experiment_id: str = EXPERIMENT_ID,
    output_suffix: str = "",
) -> dict[str, Any]:
    """Train and evaluate one binary phishing experiment.

    `exclude_sources` removes entire sources from Train and Validation only. The
    frozen Test Set is untouched, so its held-out rows form a real external-source
    evaluation.
    """

    configure_logging()
    config = load_config(config_path)
    seed = int(config["random_seed"])
    manifest = verify_binary_manifest()

    train_frame = _load_split("train")
    validation_frame = _load_split("validation")
    test_frame = _load_split("test")
    excluded = {str(value) for value in exclude_sources}
    if excluded:
        train_frame = train_frame[~train_frame["source"].astype(str).isin(excluded)].reset_index(drop=True)
        validation_frame = validation_frame[
            ~validation_frame["source"].astype(str).isin(excluded)
        ].reset_index(drop=True)
        if train_frame.empty or validation_frame.empty:
            raise ValueError("Excluding the requested sources leaves no training data")

    features = list(FEATURE_NAMES)
    x_train = extract_feature_frame(train_frame["model_url"])[features]
    y_train = _labels(train_frame)
    x_validation = extract_feature_frame(validation_frame["model_url"])[features]
    y_validation = _labels(validation_frame)
    if set(np.unique(y_train)) != {0, 1}:
        raise ValueError("Binary training split must contain BENIGN and PHISHING")

    parameters = dict(config["training"]["parameters"])
    parameters.pop("num_class", None)
    parameters["objective"] = "binary"
    parameters.pop("learning_rate", None)
    parameters.update({"learning_rate": float(config["training"]["parameters"].get("learning_rate", 0.05))})
    model = lgb.LGBMClassifier(
        **parameters,
        class_weight="balanced" if bool(config["training"]["use_class_weight"]) else None,
        verbosity=-1,
    )
    model.fit(
        x_train,
        y_train,
        eval_X=x_validation,
        eval_y=y_validation,
        eval_metric="binary_logloss",
        callbacks=[lgb.log_evaluation(period=50)],
    )

    x_test = extract_feature_frame(test_frame["model_url"])[features]
    y_test = _labels(test_frame)
    probabilities = np.asarray(model.predict_proba(x_test))
    metrics = calculate_binary_metrics(y_test, probabilities.argmax(axis=1), probabilities)

    model_dir = project_path("models/lightgbm_binary") / (output_suffix or "v1")
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.txt"
    model_path.write_text(model.booster_.model_to_string(), encoding="utf-8")
    write_feature_schema(model_dir / "feature_schema.json")
    (model_dir / "label_mapping.json").write_text(
        json.dumps(BINARY_LABEL_MAPPING, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    metrics_dir = project_path("reports/metrics/v1.3.0") / (output_suffix or "lightgbm_binary")
    figures_dir = project_path("reports/figures/v1.3.0") / (output_suffix or "lightgbm_binary")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        **metrics,
        "datasetVersion": "dataset-v1.3.0",
        "task": "binary_phishing",
        "experimentId": experiment_id,
        "excludedSources": sorted(excluded),
        "evaluationType": "external-source-holdout" if excluded else "main-frozen-test",
        "labelMapping": BINARY_LABEL_MAPPING,
        "testManifestSHA256": sha256_file(project_path(MANIFEST_PATH)),
        "testSetSHA256": manifest["views"]["binary"]["sha256"],
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "subgroups": _subgroup_metrics(test_frame, y_test, probabilities),
        "sourceSubgroups": _source_subgroups(test_frame, y_test, probabilities),
    }
    (metrics_dir / "test_metrics.json").write_text(
        json.dumps(metrics_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    plot_confusion_matrix(
        metrics["confusion_matrix"], BINARY_LABEL_NAMES, figures_dir / "confusion_matrix.png"
    )
    importance = pd.DataFrame(
        {"feature": features, "importance": model.booster_.feature_importance(importance_type="gain")}
    ).sort_values("importance", ascending=False)
    importance.head(20).to_csv(metrics_dir / "feature_importance_top20.csv", index=False)

    metadata = {
        "metadataSchemaVersion": 5,
        "experimentType": "OFFICIAL_EXPERIMENT",
        "experimentId": experiment_id,
        "modelName": "url_guardian_lightgbm_binary",
        "modelVersion": config["project"]["model_version"],
        "datasetVersion": "dataset-v1.3.0",
        "datasetView": "DOMAIN_ONLY",
        "task": "binary_phishing",
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "randomSeed": seed,
        "featureSchemaVersion": SCHEMA_VERSION,
        "featureNames": features,
        "labelMapping": BINARY_LABEL_MAPPING,
        "trainCount": int(len(train_frame)),
        "validationCount": int(len(validation_frame)),
        "testCount": int(len(test_frame)),
        "excludedSources": sorted(excluded),
        "classWeight": "balanced" if bool(config["training"]["use_class_weight"]) else None,
        "testManifestSHA256": sha256_file(project_path(MANIFEST_PATH)),
        "testSetSHA256": manifest["views"]["binary"]["sha256"],
        "modelSHA256": sha256_file(model_path),
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "libraryVersions": {
            "python": platform.python_version(),
            "lightgbm": lgb.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "testMetrics": metrics_payload,
    }
    (model_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    _update_comparison(
        project_path("reports/metrics/v1.3.0") / "baseline_comparison_v1.3.0.csv",
        {
            "Model": experiment_id,
            "Task": "binary_phishing",
            "Dataset Version": "dataset-v1.3.0",
            "Accuracy": metrics["accuracy"],
            "Precision": metrics["precision"],
            "Recall": metrics["recall"],
            "F1": metrics["f1"],
            "Specificity": metrics["specificity"],
            "Benign FPR": metrics["false_positive_rate"],
            "False Negative Rate": metrics["false_negative_rate"],
            "AUROC": metrics["auroc"],
            "AUPRC": metrics["auprc"],
            "Excluded Sources": ",".join(sorted(excluded)),
            "Model Version": config["project"]["model_version"],
            "Model SHA-256": metadata["modelSHA256"],
            "Test Manifest SHA-256": metadata["testManifestSHA256"],
            "Test Set SHA-256": metadata["testSetSHA256"],
        },
    )
    LOGGER.info(
        "%s: precision %.6f recall %.6f F1 %.6f benign FPR %.6f AUPRC %.6f",
        experiment_id,
        metrics["precision"],
        metrics["recall"],
        metrics["f1"],
        metrics["false_positive_rate"],
        metrics["auprc"],
    )
    return metrics_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate the binary phishing LightGBM model")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        train_experiment(args.config)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
