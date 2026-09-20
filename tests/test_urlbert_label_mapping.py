"""Label mapping tests: URLBERT must share the frozen three-class scheme."""

import pytest

from src.models.train_lightgbm import LABEL_MAPPING as LIGHTGBM_LABEL_MAPPING
from src.models.urlbert.config import URLBERTConfigError, load_urlbert_config
from src.models.urlbert.dataset import labels_of, load_frozen_split

EXPECTED = {"BENIGN": 0, "PHISHING": 1, "MALWARE": 2}


def test_urlbert_label_mapping_matches_the_frozen_scheme():
    config = load_urlbert_config()
    assert config.label_mapping == EXPECTED


def test_urlbert_label_mapping_matches_the_lightgbm_baseline():
    config = load_urlbert_config()
    assert config.label_mapping == dict(LIGHTGBM_LABEL_MAPPING)


def test_labels_of_preserves_frozen_order(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frame = load_frozen_split(config, "train")
    assert labels_of(frame, config) == [EXPECTED[value] for value in frame["label"]]


def test_config_rejects_an_invalid_label_mapping(tmp_path, frozen_dataset_factory):
    import yaml

    fixture = frozen_dataset_factory()
    payload = yaml.safe_load(fixture["config_path"].read_text(encoding="utf-8"))
    payload["urlbert"]["label_mapping"] = {"BENIGN": 0, "PHISHING": 2}
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(URLBERTConfigError, match="label mapping"):
        load_urlbert_config(broken)


def test_config_accepts_a_contiguous_binary_label_mapping(tmp_path, frozen_dataset_factory):
    import yaml

    fixture = frozen_dataset_factory()
    payload = yaml.safe_load(fixture["config_path"].read_text(encoding="utf-8"))
    payload["urlbert"]["label_mapping"] = {"BENIGN": 0, "PHISHING": 1}
    binary = tmp_path / "binary.yaml"
    binary.write_text(yaml.safe_dump(payload), encoding="utf-8")
    config = load_urlbert_config(binary)
    assert config.num_classes == 2
    assert config.label_names == ["BENIGN", "PHISHING"]


def test_config_rejects_a_non_domain_only_view(tmp_path, frozen_dataset_factory):
    import yaml

    fixture = frozen_dataset_factory()
    payload = yaml.safe_load(fixture["config_path"].read_text(encoding="utf-8"))
    payload["urlbert"]["dataset_view"] = "full_url"
    broken = tmp_path / "broken-view.yaml"
    broken.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(URLBERTConfigError, match="DOMAIN_ONLY"):
        load_urlbert_config(broken)
