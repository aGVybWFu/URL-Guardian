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

from src.evaluation.metrics import calculate_metrics
from src.features.extractor import extract_feature_frame
from src.features.schema import FEATURE_NAMES, SCHEMA_VERSION, write_feature_schema
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger
from src.utils.seed import set_seed
from src.data.snapshot import sha256_file

LABEL_MAPPING = {"BENIGN": 0, "PHISHING": 1, "MALWARE": 2}
LOGGER = get_logger(__name__)


def train_model(
    train: pd.DataFrame,
    validation: pd.DataFrame,
    parameters: dict[str, Any],
    use_class_weight: bool,
) -> lgb.LGBMClassifier:
    url_column = "model_url" if "model_url" in train else "normalized_url"
    x_train = extract_feature_frame(train[url_column])
    x_validation = extract_feature_frame(validation[url_column])
    y_train = train["label"].map(LABEL_MAPPING)
    y_validation = validation["label"].map(LABEL_MAPPING)
    if y_train.isna().any() or y_validation.isna().any():
        raise ValueError("Unknown label in split")
    if set(y_train.unique()) != {0, 1, 2}:
        raise ValueError("Training split must contain all three classes")
    model = lgb.LGBMClassifier(
        **parameters,
        class_weight="balanced" if use_class_weight else None,
        verbosity=-1,
    )
    model.fit(
        x_train,
        y_train,
        eval_X=x_validation,
        eval_y=y_validation,
        eval_metric="multi_logloss",
        callbacks=[lgb.log_evaluation(period=25)],
    )
    return model


def train(config_path: str | Path | None = None, view: str | None = None) -> Path:
    configure_logging()
    config = load_config(config_path)
    seed = int(config["random_seed"])
    set_seed(seed)
    experiment_mode = str(config.get("training", {}).get("experiment_mode", "FIXTURE_VERIFICATION"))
    if experiment_mode == "OFFICIAL_EXPERIMENT" and view not in {"domain_only", "full_url"}:
        raise ValueError("Official training requires an explicit dataset view")
    dataset_metadata_path = project_path(config["paths"]["dataset_metadata"])
    if not dataset_metadata_path.exists():
        raise FileNotFoundError("Build the dataset before training")
    dataset_metadata = json.loads(dataset_metadata_path.read_text(encoding="utf-8"))
    if experiment_mode == "OFFICIAL_EXPERIMENT":
        eligibility = dataset_metadata.get("viewEligibility", {})
        if not eligibility.get(view, False):
            raise ValueError(f"Official {view} experiment is not eligible")
    split_dir = project_path(config["paths"]["splits"])
    if view:
        split_dir = split_dir / view
    required_splits = [split_dir / f"{name}.csv" for name in ("train", "validation")]
    if not all(path.exists() for path in required_splits):
        readiness_path = project_path(config["paths"]["dataset_metadata"])
        if readiness_path.exists():
            readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
            if readiness.get("status") == "INCOMPLETE_SOURCE_SET":
                missing = ", ".join(readiness.get("missingLabels", []))
                raise FileNotFoundError(f"Official dataset is incomplete; missing labels: {missing}")
        raise FileNotFoundError("Dataset splits are missing. Run scripts/build_dataset.py first.")
    train_frame = pd.read_csv(split_dir / "train.csv", dtype=str, low_memory=False)
    validation_frame = pd.read_csv(split_dir / "validation.csv", dtype=str, low_memory=False)
    manifest_path = project_path(config["paths"]["splits"]) / "test_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    if experiment_mode == "OFFICIAL_EXPERIMENT" and manifest is None:
        raise FileNotFoundError("Official training requires a sealed Test Manifest")
    if manifest and manifest.get("datasetVersion") != dataset_metadata.get("datasetVersion"):
        raise ValueError("Dataset metadata and Test Manifest versions do not match")
    parameters = dict(config["training"]["parameters"])
    model = train_model(train_frame, validation_frame, parameters, bool(config["training"]["use_class_weight"]))
    url_column = "model_url" if "model_url" in validation_frame else "normalized_url"
    validation_features = extract_feature_frame(validation_frame[url_column])
    validation_true = validation_frame["label"].map(LABEL_MAPPING).to_numpy()
    validation_probabilities = model.predict_proba(validation_features)
    validation_pred = validation_probabilities.argmax(axis=1)
    validation_metrics = calculate_metrics(validation_true, validation_pred, validation_probabilities)

    model_dir = project_path(config["paths"]["model_dir"])
    if view:
        model_dir = model_dir / view
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.txt"
    model_path.write_text(model.booster_.model_to_string(), encoding="utf-8")
    write_feature_schema(model_dir / "feature_schema.json")
    (model_dir / "label_mapping.json").write_text(
        json.dumps(LABEL_MAPPING, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    model_digest = sha256_file(model_path)
    manifest_view = manifest.get("views", {}).get(view, {}) if manifest and view else {}
    metadata = {
        "metadataSchemaVersion": 2,
        "experiment_id": f"lightgbm_{view or 'legacy'}_{dataset_metadata['datasetVersion']}",
        "experimentType": experiment_mode,
        "officialExperimentEligible": bool(dataset_metadata.get("viewEligibility", {}).get(view, False)),
        "modelName": config["project"]["model_name"],
        "modelVersion": config["project"]["model_version"],
        "model_version": config["project"]["model_version"],
        "datasetView": view.upper() if view else "LEGACY",
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "randomSeed": seed,
        "random_seed": seed,
        "datasetVersion": dataset_metadata["datasetVersion"],
        "dataset_version": dataset_metadata["datasetVersion"],
        "snapshot_id": dataset_metadata.get("snapshotIds", []),
        "featureSchemaVersion": SCHEMA_VERSION,
        "featureNames": FEATURE_NAMES,
        "features": FEATURE_NAMES,
        "labelMapping": LABEL_MAPPING,
        "trainSize": len(train_frame),
        "validationSize": len(validation_frame),
        "testSize": manifest_view.get("record_count"),
        "train_count": len(train_frame),
        "validation_count": len(validation_frame),
        "test_count": manifest_view.get("record_count"),
        "unique_domains": {
            "train": int(train_frame["registrable_domain"].nunique()) if "registrable_domain" in train_frame else None,
            "validation": int(validation_frame["registrable_domain"].nunique()) if "registrable_domain" in validation_frame else None,
            "test": manifest_view.get("domain_count"),
        },
        "modelParameters": parameters,
        "parameters": parameters,
        "useClassWeight": bool(config["training"]["use_class_weight"]),
        "classWeight": "balanced" if bool(config["training"]["use_class_weight"]) else None,
        "testManifestSha256": sha256_file(manifest_path) if manifest_path.exists() else None,
        "testSetSha256": manifest_view.get("sha256"),
        "runtime": {
            "python": platform.python_version(),
            "lightgbm": lgb.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikitLearn": sklearn.__version__,
        },
        "library_versions": {
            "python": platform.python_version(),
            "lightgbm": lgb.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "model_sha256": model_digest,
        "metrics": {"validation": validation_metrics},
    }
    (model_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LOGGER.info("Saved LightGBM model to %s", model_path)
    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the URL Guardian LightGBM baseline")
    parser.add_argument("--config", default=None)
    parser.add_argument("--view", choices=["domain_only", "full_url"], default=None)
    parser.add_argument("--all", action="store_true", help="Train both official dataset views")
    args = parser.parse_args()
    try:
        if args.all:
            for view in ("domain_only", "full_url"):
                train(args.config, view)
        else:
            train(args.config, args.view)
    except (FileNotFoundError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
