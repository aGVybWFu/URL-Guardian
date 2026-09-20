import json

import pandas as pd
import yaml

from scripts.build_dataset import build_dataset


def test_dataset_build_pipeline_writes_group_safe_splits(tmp_path):
    raw_root = tmp_path / "raw"
    labels = (("benign", "BENIGN"), ("phishing", "PHISHING"), ("malware", "MALWARE"))
    for folder, label in labels:
        directory = raw_root / folder
        directory.mkdir(parents=True)
        pd.DataFrame(
            {
                "url": [f"https://{folder}-{index}.test/{label.lower()}" for index in range(12)],
                "label": label,
                "source": "safe-fixture",
                "collected_at": "2026-09-20",
            }
        ).to_csv(directory / "fixture.csv", index=False)
    config = {
        "project": {"dataset_version": "fixture", "model_name": "fixture", "model_version": "fixture"},
        "random_seed": 42,
        "split": {"train_ratio": 0.7, "validation_ratio": 0.15, "test_ratio": 0.15,
                  "method": "registrable_domain_group_split"},
        "training": {"use_class_weight": False, "parameters": {}},
        "paths": {
            "raw": str(raw_root), "processed": str(tmp_path / "processed" / "dataset.csv"),
            "splits": str(tmp_path / "splits"), "conflicts": str(tmp_path / "conflicts.csv"),
            "dataset_metadata": str(tmp_path / "processed" / "dataset_metadata.json"),
            "model_dir": str(tmp_path / "model"), "figures": str(tmp_path / "figures"),
            "metrics": str(tmp_path / "metrics"),
            "domain_conflicts": str(tmp_path / "domain-conflicts.csv"),
            "domain_only_conflicts": str(tmp_path / "domain-only-conflicts.csv"),
            "dataset_bias": str(tmp_path / "dataset-bias"),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    metadata = build_dataset(config_path)
    assert metadata["numberOfRows"] == 36
    assert metadata["domainLeakage"] == 0
    assert sum(metadata["splits"]["domain_only"][key] for key in ("trainSize", "validationSize", "testSize")) == 36
    persisted = json.loads((tmp_path / "processed" / "dataset_metadata.json").read_text(encoding="utf-8"))
    assert persisted["splitMethod"] == "registrable_domain_group_split"
    assert all(
        (tmp_path / "splits" / "domain_only" / f"{name}.csv").exists()
        for name in ("train", "validation", "test")
    )
