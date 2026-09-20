"""Frozen dataset contract tests for Phase 2 URLBERT."""

import pytest

from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.dataset import (
    DatasetContractError,
    build_row_ids,
    load_frozen_split,
    load_training_frames,
    validate_frozen_contract,
    validate_no_domain_leakage,
    validate_text_contract,
)


def test_training_path_never_requires_the_test_csv(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    test_path = config.splits_dir / "test.csv"
    test_path.unlink()
    frames = load_training_frames(config)
    assert set(frames) == {"train", "validation"}
    summary = validate_frozen_contract(config, frames, require_all_splits=False)
    assert summary["domainLeakage"] == 0
    assert set(summary["splits"]) == {"train", "validation"}


def test_row_identity_is_the_positional_frozen_index(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    for split in ("train", "validation", "test"):
        frame = load_frozen_split(config, split)
        assert build_row_ids(split, len(frame)) == [f"{split}:{index}" for index in range(len(frame))]
        assert frame[config.text_column].tolist() == fixture["frames"][split][config.text_column].tolist()


def test_text_contract_rejects_inconsistent_domain_representation(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frame = load_frozen_split(config, "train").copy()
    validate_text_contract(frame, config)
    frame.loc[0, "model_url"] = "https://tampered.example.test/"
    with pytest.raises(DatasetContractError, match="DOMAIN_ONLY"):
        validate_text_contract(frame, config)


def test_label_contract_rejects_unknown_labels(frozen_dataset_factory, real_urlbert_tokenizer):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frame = load_frozen_split(config, "train").copy()
    frame.loc[0, "label"] = "SPAM"
    frames = {"train": frame, "validation": load_frozen_split(config, "validation")}
    with pytest.raises(DatasetContractError, match="Unknown labels"):
        validate_frozen_contract(config, frames, require_all_splits=False)


def test_domain_leakage_is_detected(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    train = load_frozen_split(config, "train")
    validation = load_frozen_split(config, "validation").copy()
    leaked_domain = train["registrable_domain"].iloc[0]
    validation.loc[0, "registrable_domain"] = leaked_domain
    validation.loc[0, "model_url"] = f"https://{leaked_domain}/"
    with pytest.raises(DatasetContractError, match="leakage"):
        validate_no_domain_leakage({"train": train, "validation": validation})


def test_full_contract_requires_all_three_splits(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frames = {
        split: load_frozen_split(config, split) for split in ("train", "validation", "test")
    }
    summary = validate_frozen_contract(config, frames, require_all_splits=True)
    assert set(summary["splits"]) == {"train", "validation", "test"}
    assert all(entry["rowCount"] > 0 for entry in summary["splits"].values())
