import json

import pytest
import yaml

from src.models.train_lightgbm import train


def test_official_training_refuses_ineligible_view(tmp_path):
    metadata = tmp_path / "dataset_metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "datasetVersion": "dataset-v1.1.0",
                "officialExperimentEligible": False,
                "viewEligibility": {"domain_only": False, "full_url": False},
            }
        ),
        encoding="utf-8",
    )
    config = {
        "project": {"dataset_version": "dataset-v1.1.0", "model_name": "test", "model_version": "test"},
        "random_seed": 42,
        "training": {"experiment_mode": "OFFICIAL_EXPERIMENT", "use_class_weight": True, "parameters": {}},
        "paths": {
            "dataset_metadata": str(metadata),
            "splits": str(tmp_path / "splits"),
            "model_dir": str(tmp_path / "models"),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ValueError, match="not eligible"):
        train(config_path, "domain_only")
