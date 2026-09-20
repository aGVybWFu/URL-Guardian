"""Frozen dataset contract and torch datasets for Phase 2 URLBERT.

Design rules enforced here:

* The dataset text is the frozen `DOMAIN_ONLY` representation
  (`https://<registrable_domain>/`). The model input is the registrable-domain
  string that produced it, verified to be consistent for every row.
* Row identity is the positional row index of the frozen CSV, so a URLBERT row
  id equals the official split row id by construction.
* The sealed Test Manifest is verified before training and before evaluation.
  Test rows are never loaded on the training path.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset
from src.data.snapshot import sha256_file
from src.models.urlbert.config import URLBERTConfig

SPLITS: tuple[str, ...] = ("train", "validation", "test")
TRAINING_SPLITS: tuple[str, ...] = ("train", "validation")


class DatasetContractError(RuntimeError):
    """Raised when the frozen dataset contract is violated."""


def verify_frozen_test_manifest(
    config: URLBERTConfig,
    *,
    verify_test_files: bool = True,
) -> dict[str, object]:
    """Verify the sealed Test Manifest hash and its recorded Test file hashes."""

    manifest_path = config.raw_path("test_manifest")
    if not manifest_path.exists():
        raise DatasetContractError("Frozen Test Manifest is missing; stop before training or evaluation")
    expected_manifest = str(config.raw.get("expected_test_manifest_sha256", "")).strip()
    actual_manifest = sha256_file(manifest_path)
    if expected_manifest and actual_manifest != expected_manifest:
        raise DatasetContractError(
            "Frozen Test Manifest SHA-256 does not match the accepted baseline value"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("datasetVersion") != config.dataset_version:
        raise DatasetContractError("Test Manifest dataset version does not match the URLBERT config")
    view_entry = manifest.get("views", {}).get(config.manifest_view)
    if not isinstance(view_entry, dict):
        raise DatasetContractError("Test Manifest has no entry for the configured dataset view")
    expected_test = str(config.raw.get("expected_test_sha256", "")).strip()
    if expected_test and view_entry.get("sha256") != expected_test:
        raise DatasetContractError("Sealed Test Set hash differs from the accepted baseline value")
    if verify_test_files:
        test_path = config.splits_dir / "test.csv"
        if not test_path.exists():
            raise DatasetContractError("Sealed Test CSV is missing")
        if sha256_file(test_path) != view_entry.get("sha256"):
            raise DatasetContractError("Sealed Test CSV no longer matches the Test Manifest")
    return manifest


def load_frozen_split(config: URLBERTConfig, split: str) -> pd.DataFrame:
    """Load one frozen split CSV as strings."""

    if split not in SPLITS:
        raise DatasetContractError(f"Unknown split: {split}")
    path = config.splits_dir / f"{split}.csv"
    if not path.exists():
        raise DatasetContractError(f"Frozen split is missing: {path.name}")
    return pd.read_csv(path, dtype=str, low_memory=False)


def load_training_frames(config: URLBERTConfig) -> dict[str, pd.DataFrame]:
    """Load only Train and Validation. The Test CSV is intentionally never opened here."""

    return {split: load_frozen_split(config, split) for split in TRAINING_SPLITS}


def validate_text_contract(frame: pd.DataFrame, config: URLBERTConfig) -> None:
    """Verify that the model text is exactly the frozen DOMAIN_ONLY domain string."""

    column = config.text_column
    if column not in frame.columns:
        raise DatasetContractError(f"Frozen split is missing the text column: {column}")
    if "model_url" not in frame.columns:
        raise DatasetContractError("Frozen split is missing the DOMAIN_ONLY model_url column")
    text = frame[column].astype(str)
    if text.isna().any() or (text.str.strip() == "").any():
        raise DatasetContractError("Frozen split contains empty domain text")
    expected = "https://" + text + "/"
    if not bool(expected.eq(frame["model_url"].astype(str)).all()):
        raise DatasetContractError(
            "Frozen DOMAIN_ONLY representation is not consistent with the configured text column"
        )


def validate_label_contract(frame: pd.DataFrame, config: URLBERTConfig) -> None:
    """Verify that every label maps to the fixed three-class scheme."""

    if "label" not in frame.columns:
        raise DatasetContractError("Frozen split is missing the label column")
    unknown = sorted(set(frame["label"].astype(str)).difference(config.label_mapping))
    if unknown:
        raise DatasetContractError(f"Unknown labels in frozen split: {unknown}")


def validate_no_domain_leakage(frames: dict[str, pd.DataFrame]) -> None:
    """Verify the frozen split still has zero registrable-domain overlap."""

    domains = {
        split: set(frame["registrable_domain"].astype(str))
        for split, frame in frames.items()
    }
    names = sorted(domains)
    for index, first in enumerate(names):
        for second in names[index + 1 :]:
            overlap = domains[first].intersection(domains[second])
            if overlap:
                raise DatasetContractError(
                    f"Registrable-domain leakage detected between {first} and {second}: {len(overlap)} domains"
                )


def validate_frozen_contract(
    config: URLBERTConfig,
    frames: dict[str, pd.DataFrame],
    *,
    require_all_splits: bool,
) -> dict[str, object]:
    """Validate the frozen contract and return a machine-checkable summary."""

    if require_all_splits and set(frames) != set(SPLITS):
        raise DatasetContractError("Full contract validation requires train, validation and test")
    if not require_all_splits and set(frames) != set(TRAINING_SPLITS):
        raise DatasetContractError("Training contract validation requires train and validation only")
    metadata_path = config.raw_path("dataset_metadata")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("datasetVersion") != config.dataset_version:
        raise DatasetContractError("Dataset metadata version does not match the URLBERT config")
    for split, frame in frames.items():
        validate_text_contract(frame, config)
        validate_label_contract(frame, config)
    validate_no_domain_leakage(frames)
    summary: dict[str, object] = {
        "datasetVersion": config.dataset_version,
        "datasetView": config.dataset_view,
        "textColumn": config.text_column,
        "splits": {
            split: {
                "rowCount": int(len(frame)),
                "uniqueDomains": int(frame["registrable_domain"].nunique()),
                "labelDistribution": {
                    str(key): int(value)
                    for key, value in frame["label"].value_counts().sort_index().items()
                },
                "textSha256": hashlib.sha256(
                    "\n".join(frame[config.text_column].astype(str)).encode("utf-8")
                ).hexdigest(),
            }
            for split, frame in sorted(frames.items())
        },
        "domainLeakage": 0,
    }
    return summary


def labels_of(frame: pd.DataFrame, config: URLBERTConfig) -> list[int]:
    """Map frozen labels to the fixed integer scheme."""

    return [int(config.label_mapping[str(value)]) for value in frame["label"].astype(str)]


def texts_of(frame: pd.DataFrame, config: URLBERTConfig) -> list[str]:
    """Return the exact model input strings, preserving frozen row order."""

    return frame[config.text_column].astype(str).tolist()


@dataclass(frozen=True)
class TokenizedSplit:
    """Tokenized tensors plus the frozen row identifiers they came from."""

    split: str
    row_ids: list[str]
    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    labels: torch.Tensor

    def __len__(self) -> int:
        return int(self.labels.shape[0])


def build_row_ids(split: str, count: int) -> list[str]:
    """Deterministic row identity: positional index inside the frozen split."""

    return [f"{split}:{position}" for position in range(count)]


def tokenize_frame(
    frame: pd.DataFrame,
    split: str,
    config: URLBERTConfig,
    tokenizer: object,
) -> TokenizedSplit:
    """Tokenize a frozen split without altering row order."""

    texts = texts_of(frame, config)
    encoded = tokenizer(
        texts,
        padding="max_length",
        truncation=True,
        max_length=config.max_length,
        return_tensors="pt",
    )
    labels = torch.tensor(labels_of(frame, config), dtype=torch.long)
    return TokenizedSplit(
        split=split,
        row_ids=build_row_ids(split, len(texts)),
        input_ids=encoded["input_ids"].to(torch.long),
        attention_mask=encoded["attention_mask"].to(torch.long),
        labels=labels,
    )


class DomainOnlyDataset(Dataset):
    """A torch Dataset over an already tokenized frozen split."""

    def __init__(self, tokenized: TokenizedSplit) -> None:
        self.tokenized = tokenized

    def __len__(self) -> int:
        return len(self.tokenized)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
        return {
            "input_ids": self.tokenized.input_ids[index],
            "attention_mask": self.tokenized.attention_mask[index],
            "labels": self.tokenized.labels[index],
        }


def token_length_statistics(
    frames: Iterable[pd.DataFrame],
    config: URLBERTConfig,
    tokenizer: object,
) -> dict[str, float]:
    """Token-length distribution used to justify `max_length`.

    Only Train/Validation frames may be passed here; the Test Set must not
    influence the max_length decision.
    """

    lengths: list[int] = []
    for frame in frames:
        encoded = tokenizer(
            texts_of(frame, config),
            add_special_tokens=True,
            truncation=False,
        )["input_ids"]
        lengths.extend(len(ids) for ids in encoded)
    if not lengths:
        raise DatasetContractError("Token-length analysis received no rows")
    series = pd.Series(lengths, dtype="int64")
    return {
        "count": int(series.size),
        "p50": float(series.quantile(0.50)),
        "p90": float(series.quantile(0.90)),
        "p95": float(series.quantile(0.95)),
        "p99": float(series.quantile(0.99)),
        "max": float(series.max()),
        "mean": float(series.mean()),
    }


def class_weights_from_labels(labels: Sequence[int], num_classes: int = 3) -> list[float]:
    """Balanced class weights computed only from the supplied (training) labels."""

    from sklearn.utils.class_weight import compute_class_weight

    values = list(labels)
    if not values:
        raise DatasetContractError("Cannot compute class weights without training labels")
    classes = np.arange(num_classes)
    weights = compute_class_weight("balanced", classes=classes, y=np.asarray(values, dtype=int))
    return [float(weight) for weight in weights]
