"""Guard tests proving the Test Set cannot influence training decisions."""

from pathlib import Path

import pytest

from src.models.urlbert import train as train_module
from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.dataset import TRAINING_SPLITS, load_training_frames

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_training_splits_are_train_and_validation_only():
    assert TRAINING_SPLITS == ("train", "validation")


def test_training_module_never_loads_the_test_split():
    source = (REPO_ROOT / "src" / "models" / "urlbert" / "train.py").read_text(encoding="utf-8")
    assert 'load_frozen_split' not in source
    assert '"test"' not in source
    assert "test.csv" not in source


def test_training_verifies_the_manifest_without_opening_the_test_csv(frozen_dataset_factory):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    (config.splits_dir / "test.csv").unlink()
    frames = load_training_frames(config)
    assert set(frames) == {"train", "validation"}
    assert train_module.verify_frozen_test_manifest.__module__ == "src.models.urlbert.dataset"


def test_early_stopping_uses_validation_macro_f1_only():
    source = (REPO_ROOT / "src" / "models" / "urlbert" / "train.py").read_text(encoding="utf-8")
    assert 'early_stopping_metric", "macro_f1"' in source or "selectionValue" in source
    assert 'if entry["selectionValue"] > best_macro_f1:' in source
    # The selection value must come from the validation entry, never from test data.
    entry_function = source.split("def _epoch_entry")[1].split("def _loader_versions")[0]
    assert '"selectionValue": float(validation_metrics["macro_f1"])' in entry_function
    assert '"selectionValue": float(validation_metrics["f1"])' in entry_function
    assert "test" not in entry_function.lower().replace("latest", "")


def test_evaluation_is_the_only_place_that_reads_test_rows():
    evaluate_source = (REPO_ROOT / "src" / "models" / "urlbert" / "evaluate.py").read_text(encoding="utf-8")
    analysis_source = (REPO_ROOT / "src" / "models" / "urlbert" / "analysis.py").read_text(encoding="utf-8")
    assert 'load_frozen_split(urlbert, "test")' in evaluate_source
    assert "test_predictions.csv" in analysis_source
    assert "test.csv" not in analysis_source


def test_class_weights_are_derived_from_train_labels_only(frozen_dataset_factory):
    from src.models.urlbert.dataset import class_weights_from_labels, labels_of

    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frames = load_training_frames(config)
    train_weights = class_weights_from_labels(labels_of(frames["train"], config))
    shifted = labels_of(frames["train"], config)[:-3] + [0, 0, 0]
    shifted_weights = class_weights_from_labels(shifted)
    assert len(train_weights) == 3
    assert train_weights != shifted_weights
    source = (REPO_ROOT / "src" / "models" / "urlbert" / "train.py").read_text(encoding="utf-8")
    assert 'class_weights_from_labels(labels_of(frames["train"], urlbert), urlbert.num_classes)' in source
