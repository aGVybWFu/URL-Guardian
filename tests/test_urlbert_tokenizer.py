"""Tokenizer tests for the frozen DOMAIN_ONLY text representation."""

import pytest

from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.dataset import (
    load_frozen_split,
    token_length_statistics,
    tokenize_frame,
    texts_of,
)

EXPECTED_SPECIAL_TOKENS = {
    "unk_token": "[UNK]",
    "sep_token": "[SEP]",
    "pad_token": "[PAD]",
    "cls_token": "[CLS]",
    "mask_token": "[MASK]",
}


def test_tokenizer_special_tokens_match_the_model_card(real_urlbert_tokenizer):
    special = {key: str(value) for key, value in real_urlbert_tokenizer.special_tokens_map.items()}
    for key, value in EXPECTED_SPECIAL_TOKENS.items():
        assert special.get(key) == value


def test_tokenizer_handles_domain_only_text(real_urlbert_tokenizer):
    encoded = real_urlbert_tokenizer(
        ["example.com", "login-verify.example.test", "192.0.2.1"],
        padding="max_length",
        truncation=True,
        max_length=32,
        return_tensors="pt",
    )
    assert tuple(encoded["input_ids"].shape) == (3, 32)
    assert int(encoded["attention_mask"].sum()) > 0


def test_tokenize_frame_preserves_row_order_and_length(frozen_dataset_factory, real_urlbert_tokenizer):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frame = load_frozen_split(config, "validation")
    tokenized = tokenize_frame(frame, "validation", config, real_urlbert_tokenizer)
    assert len(tokenized) == len(frame)
    assert tokenized.input_ids.shape == (len(frame), config.max_length)
    assert tokenized.row_ids == [f"validation:{index}" for index in range(len(frame))]
    assert texts_of(frame, config) == frame[config.text_column].astype(str).tolist()


def test_declared_max_length_covers_the_observed_domain_lengths(frozen_dataset_factory, real_urlbert_tokenizer):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    frames = [load_frozen_split(config, split) for split in ("train", "validation")]
    statistics = token_length_statistics(frames, config, real_urlbert_tokenizer)
    assert statistics["count"] > 0
    assert statistics["max"] <= config.max_length
    for key in ("p50", "p90", "p95", "p99", "max", "mean"):
        assert key in statistics


def test_official_max_length_is_justified_by_train_and_validation():
    """The official 32-token decision must still cover Train/Validation fully."""

    import pandas as pd

    config = load_urlbert_config()
    splits_dir = config.splits_dir
    if not (splits_dir / "train.csv").exists():
        pytest.skip("Frozen DOMAIN_ONLY splits are not present in this environment")
    frames = [
        pd.read_csv(splits_dir / f"{split}.csv", dtype=str, low_memory=False)
        for split in ("train", "validation")
    ]
    observed_max = max(frame[config.text_column].astype(str).str.len().max() for frame in frames)
    assert config.max_length >= 32
    assert observed_max <= 253
