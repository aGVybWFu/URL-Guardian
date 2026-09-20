import json

import pandas as pd
import yaml

from scripts.build_dataset import build_dataset
from src.evaluation.evaluate import evaluate
from src.models.train_lightgbm import train


def test_both_dataset_views_train_evaluate_and_share_sealed_test_domains(tmp_path):
    raw = tmp_path / "raw"
    for folder, label in (("benign", "BENIGN"), ("phishing", "PHISHING"), ("malware", "MALWARE")):
        directory = raw / folder
        directory.mkdir(parents=True)
        pd.DataFrame(
            {
                "url": [f"https://{folder}-{index}.test/{label.lower()}?id={index}" for index in range(14)],
                "label": label,
                "source": "safe-fixture",
                "collected_at": "2026-09-20",
            }
        ).to_csv(directory / "fixture.csv", index=False)
    config = {
        "project": {"dataset_version": "fixture-v1", "model_name": "fixture", "model_version": "fixture"},
        "random_seed": 42,
        "dataset": {"target_per_class": 14},
        "split": {"train_ratio": 0.7, "validation_ratio": 0.15, "test_ratio": 0.15,
                  "method": "registrable_domain_group_split"},
        "training": {"use_class_weight": False, "parameters": {
            "objective": "multiclass", "num_class": 3, "n_estimators": 12, "learning_rate": 0.1,
            "num_leaves": 7, "min_child_samples": 1, "random_state": 42, "n_jobs": 1,
            "deterministic": True, "force_col_wise": True,
        }},
        "paths": {
            "raw": str(raw), "processed": str(tmp_path / "processed" / "dataset.csv"),
            "splits": str(tmp_path / "splits"), "conflicts": str(tmp_path / "reports" / "conflicts.csv"),
            "domain_conflicts": str(tmp_path / "reports" / "domain-conflicts.csv"),
            "domain_only_conflicts": str(tmp_path / "reports" / "domain-only-conflicts.csv"),
            "dataset_metadata": str(tmp_path / "processed" / "dataset_metadata.json"),
            "model_dir": str(tmp_path / "models"), "figures": str(tmp_path / "figures"),
            "metrics": str(tmp_path / "metrics"), "dataset_bias": str(tmp_path / "bias"),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    metadata = build_dataset(config_path)
    assert metadata["domainLeakage"] == 0
    manifest = json.loads((tmp_path / "splits" / "test_manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["views"]) == {"domain_only", "full_url"}
    for view in ("domain_only", "full_url"):
        model_path = train(config_path, view)
        metrics = evaluate(config_path, view)
        assert model_path.exists()
        assert metrics["auroc_ovr_macro"] is not None
        assert metrics["auprc_ovr_macro"] is not None
    comparison = pd.read_csv(tmp_path / "metrics" / "baseline_comparison.csv")
    assert set(comparison["Dataset View"]) == {"DOMAIN_ONLY", "FULL_URL"}
