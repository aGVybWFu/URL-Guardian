import json

import pandas as pd
import yaml

from src.evaluation.evaluate import evaluate
from src.models.predict import predict_url
from src.models.train_lightgbm import train


def _model_frame(start: int, count: int) -> pd.DataFrame:
    rows = []
    for index in range(start, start + count):
        rows.extend(
            [
                {"normalized_url": f"https://normal-{index}.test/docs/index", "label": "BENIGN"},
                {"normalized_url": f"http://verify-account-{index}.test/login?confirm={index}", "label": "PHISHING"},
                {"normalized_url": f"http://192.0.2.{index % 200 + 1}:8080/file-{index}.exe?download=1", "label": "MALWARE"},
            ]
        )
    return pd.DataFrame(rows)


def test_lightgbm_model_pipeline_saves_evaluates_and_predicts(tmp_path):
    train_frame = _model_frame(1, 15)
    validation_frame = _model_frame(100, 5)
    test_frame = _model_frame(200, 5)
    split_dir = tmp_path / "splits"
    split_dir.mkdir()
    for name, frame in (("train", train_frame), ("validation", validation_frame), ("test", test_frame)):
        frame.to_csv(split_dir / f"{name}.csv", index=False)
    metadata_path = tmp_path / "dataset_metadata.json"
    metadata_path.write_text(json.dumps({"datasetVersion": "safe-fixture-only"}), encoding="utf-8")
    config = {
        "project": {"dataset_version": "safe-fixture-only", "model_name": "test", "model_version": "test"},
        "random_seed": 42,
        "split": {"train_ratio": 0.7, "validation_ratio": 0.15, "test_ratio": 0.15,
                  "method": "registrable_domain_group_split"},
        "training": {
            "use_class_weight": False,
            "parameters": {
                "objective": "multiclass", "num_class": 3, "n_estimators": 20,
                "learning_rate": 0.1, "num_leaves": 7, "min_child_samples": 1,
                "random_state": 42, "n_jobs": 1, "deterministic": True, "force_col_wise": True,
            },
        },
        "paths": {
            "raw": str(tmp_path / "raw"), "processed": str(tmp_path / "dataset.csv"),
            "splits": str(split_dir), "conflicts": str(tmp_path / "conflicts.csv"),
            "dataset_metadata": str(metadata_path), "model_dir": str(tmp_path / "研究模型"),
            "figures": str(tmp_path / "figures"), "metrics": str(tmp_path / "metrics"),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    model_path = train(config_path)
    metrics = evaluate(config_path)
    prediction = predict_url("https://example.com/login", config_path)
    assert model_path.exists()
    assert (tmp_path / "研究模型" / "metadata.json").exists()
    assert (tmp_path / "figures" / "confusion_matrix.png").exists()
    assert (tmp_path / "figures" / "feature_importance.png").exists()
    assert (tmp_path / "metrics" / "feature_importance.csv").exists()
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert set(prediction["probabilities"]) == {"BENIGN", "PHISHING", "MALWARE"}
    assert abs(sum(prediction["probabilities"].values()) - 1.0) < 1e-6
