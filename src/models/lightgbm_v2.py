"""Phase 2.5 LightGBM V2 training and evaluation on dataset-v1.2.0.

Two official experiments are produced on the same frozen splits:

* `LightGBM_DOMAIN_ONLY_V2`         - the existing 43-feature schema.
* `LightGBM_DOMAIN_ONLY_V2_NOIP`    - the same schema minus the IP-indicator
  features, so the ablation shows how much MALWARE detection depended on them.

Evaluation always happens once, on the regime's sealed Test Set, and always
reports host-type subgroup metrics so the IP versus non-IP gap stays visible.
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

from src.data.hosttype import classify_host_type
from src.data.snapshot import sha256_file
from src.evaluation.metrics import LABEL_NAMES, calculate_metrics
from src.evaluation.plots import plot_confusion_matrix
from src.features.extractor import extract_feature_frame
from src.features.schema import FEATURE_NAMES, SCHEMA_VERSION, write_feature_schema
from src.models.train_lightgbm import LABEL_MAPPING
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
IP_FEATURES = ["has_ip_address", "has_ipv4", "has_ipv6"]
EXPERIMENTS = {
    "full": {"experimentId": "LightGBM_DOMAIN_ONLY_V2", "excludedFeatures": []},
    "no_ip": {"experimentId": "LightGBM_DOMAIN_ONLY_V2_NOIP", "excludedFeatures": IP_FEATURES},
}


def _feature_list(excluded: list[str]) -> list[str]:
    return [name for name in FEATURE_NAMES if name not in set(excluded)]


def _subgroup_metrics(frame: pd.DataFrame, y_true: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    """Metrics restricted to IP-hosted and domain-hosted Test rows."""

    host_types = frame["host_type"].astype(str).to_numpy()
    predicted = probabilities.argmax(axis=1)
    output: dict[str, Any] = {}
    for name, mask in (("ip_host", host_types != "DOMAIN"), ("non_ip_host", host_types == "DOMAIN")):
        if not mask.any():
            output[name] = {"sampleCount": 0}
            continue
        metrics = calculate_metrics(y_true[mask], predicted[mask], probabilities[mask])
        present = sorted({int(value) for value in y_true[mask]})
        output[name] = {
            "sampleCount": int(mask.sum()),
            "presentClasses": ",".join(LABEL_NAMES[index] for index in present),
            "macroF1Note": (
                "Single-class subgroup: macro averages are computed over all three labels, so they are "
                "not interpretable here. Use per-class recall and support instead."
                if len(present) == 1
                else None
            ),
            "accuracy": metrics["accuracy"],
            "macroF1": metrics["macro_f1"],
            "macroPrecision": metrics["macro_precision"],
            "macroRecall": metrics["macro_recall"],
            "malwareRecall": metrics["malware_recall"],
            "malwareSupport": int((y_true[mask] == 2).sum()),
            "phishingRecall": metrics["phishing_recall"],
            "benignFpr": metrics["benign_false_positive_rate"],
            "maliciousFnr": metrics["malicious_false_negative_rate"],
        }
    return output


def _update_comparison(path: Path, row: dict[str, object]) -> None:
    frame = pd.read_csv(path) if path.exists() else pd.DataFrame()
    if not frame.empty:
        frame = frame[~((frame["Model"] == row["Model"]) & (frame["Dataset View"] == row["Dataset View"]))]
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([frame, pd.DataFrame([row])], ignore_index=True).to_csv(path, index=False)


def train_experiment(
    config_path: str | Path | None,
    experiment: str,
    regime: str,
) -> dict[str, Any]:
    """Train and evaluate one LightGBM V2 experiment on the frozen v1.2.0 splits."""

    configure_logging()
    if experiment not in EXPERIMENTS:
        raise ValueError(f"Unknown experiment: {experiment}")
    config = load_config(config_path)
    seed = int(config["random_seed"])
    splits_root = project_path("data/splits/v1.2.0") / regime
    test_path = splits_root / "test.csv"
    if not test_path.exists():
        raise FileNotFoundError("Build dataset-v1.2.0 before training")
    manifest_path = project_path("data/splits/v1.2.0") / "test_manifest_v1.2.0.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = manifest["views"][regime]["sha256"]
    if sha256_file(test_path) != expected:
        raise RuntimeError("Sealed v1.2.0 Test Set does not match test_manifest_v1.2.0.json")

    metadata_path = project_path("data/processed/v1.2.0/dataset_metadata.json")
    dataset_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if dataset_metadata.get("datasetVersion") != "dataset-v1.2.0":
        raise ValueError("dataset-v1.2.0 metadata is missing")

    train_frame = pd.read_csv(splits_root / "train.csv", dtype=str, low_memory=False)
    validation_frame = pd.read_csv(splits_root / "validation.csv", dtype=str, low_memory=False)
    test_frame = pd.read_csv(test_path, dtype=str, low_memory=False)

    specification = EXPERIMENTS[experiment]
    excluded = list(specification["excludedFeatures"])
    features = _feature_list(excluded)

    x_train = extract_feature_frame(train_frame["model_url"])[features]
    y_train = train_frame["label"].map(LABEL_MAPPING)
    x_validation = extract_feature_frame(validation_frame["model_url"])[features]
    y_validation = validation_frame["label"].map(LABEL_MAPPING)
    if y_train.isna().any() or y_validation.isna().any():
        raise ValueError("Unknown label in the frozen v1.2.0 splits")

    parameters = dict(config["training"]["parameters"])
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
        eval_metric="multi_logloss",
        callbacks=[lgb.log_evaluation(period=50)],
    )

    x_test = extract_feature_frame(test_frame["model_url"])[features]
    y_true = test_frame["label"].map(LABEL_MAPPING).to_numpy(dtype=int)
    probabilities = np.asarray(model.predict_proba(x_test))
    metrics = calculate_metrics(y_true, probabilities.argmax(axis=1), probabilities)
    subgroups = _subgroup_metrics(test_frame, y_true, probabilities)

    model_dir = project_path("models/lightgbm_v2") / f"{regime}_{experiment}"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.txt"
    model_path.write_text(model.booster_.model_to_string(), encoding="utf-8")
    write_feature_schema(model_dir / "feature_schema.json")
    (model_dir / "label_mapping.json").write_text(
        json.dumps(LABEL_MAPPING, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    metrics_dir = project_path("reports/metrics/v1.2.0") / f"{regime}_{experiment}"
    figures_dir = project_path("reports/figures/v1.2.0") / f"{regime}_{experiment}"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        **metrics,
        "datasetVersion": "dataset-v1.2.0",
        "regime": regime,
        "experimentId": specification["experimentId"],
        "excludedFeatures": excluded,
        "featureCount": len(features),
        "subgroups": subgroups,
        "testManifestSHA256": manifest_path and sha256_file(manifest_path),
        "testSetSHA256": expected,
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "labelNames": LABEL_NAMES,
    }
    (metrics_dir / "test_metrics.json").write_text(
        json.dumps(metrics_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    plot_confusion_matrix(metrics["confusion_matrix"], LABEL_NAMES, figures_dir / "confusion_matrix.png")
    importance = pd.DataFrame(
        {"feature": features, "importance": model.booster_.feature_importance(importance_type="gain")}
    ).sort_values("importance", ascending=False)
    importance.head(20).to_csv(metrics_dir / "feature_importance_top20.csv", index=False)

    metadata = {
        "metadataSchemaVersion": 3,
        "experimentType": "OFFICIAL_EXPERIMENT",
        "experimentId": specification["experimentId"],
        "modelName": "url_guardian_lightgbm",
        "modelVersion": config["project"]["model_version"],
        "datasetVersion": "dataset-v1.2.0",
        "datasetRegime": regime,
        "datasetView": "DOMAIN_ONLY",
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "randomSeed": seed,
        "featureSchemaVersion": SCHEMA_VERSION,
        "featureNames": features,
        "excludedFeatures": excluded,
        "labelMapping": LABEL_MAPPING,
        "trainCount": int(len(train_frame)),
        "validationCount": int(len(validation_frame)),
        "testCount": int(len(test_frame)),
        "classWeight": "balanced" if bool(config["training"]["use_class_weight"]) else None,
        "testManifestSHA256": sha256_file(manifest_path),
        "testSetSHA256": expected,
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
        project_path("reports/metrics/v1.2.0") / "baseline_comparison_v1.2.0.csv",
        {
            "Model": specification["experimentId"],
            "Dataset View": "DOMAIN_ONLY",
            "Dataset Version": "dataset-v1.2.0",
            "Regime": regime,
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
            "Non-IP Malware Recall": subgroups["non_ip_host"].get("malwareRecall"),
            "IP Malware Recall": subgroups["ip_host"].get("malwareRecall"),
            "Feature Count": len(features),
            "Model Version": config["project"]["model_version"],
            "Model SHA-256": metadata["modelSHA256"],
            "Test Manifest SHA-256": metadata["testManifestSHA256"],
            "Test Set SHA-256": expected,
        },
    )
    LOGGER.info(
        "%s/%s test accuracy %.6f macro F1 %.6f malware recall %.6f",
        regime,
        experiment,
        metrics["accuracy"],
        metrics["macro_f1"],
        metrics["malware_recall"],
    )
    return metrics_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate LightGBM V2 on dataset-v1.2.0")
    parser.add_argument("--config", default=None)
    parser.add_argument("--regime", default="artifact_controlled", choices=["artifact_controlled", "natural"])
    parser.add_argument("--experiment", default="all", choices=["full", "no_ip", "all"])
    parser.add_argument("--view", default="domain_only")
    args = parser.parse_args()
    experiments = ["full", "no_ip"] if args.experiment == "all" else [args.experiment]
    try:
        for experiment in experiments:
            train_experiment(args.config, experiment, args.regime)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
