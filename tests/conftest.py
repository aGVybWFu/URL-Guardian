"""Shared fixtures for Phase 2 URLBERT tests.

A tiny randomly initialized ModernBERT encoder is used for logic tests so that
unit tests stay fast and hermetic. The real pretrained encoder is only required
by the official Phase 2 run, not by the test suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest
import yaml

from src.data.manifest import build_test_manifest, seal_test_manifest
from src.data.snapshot import sha256_file

DATASET_VERSION = "dataset-v1.1.0"
LABEL_MAPPING = {"BENIGN": 0, "PHISHING": 1, "MALWARE": 2}


@pytest.fixture(scope="session")
def tiny_modernbert_config():
    transformers = pytest.importorskip("transformers")
    return transformers.ModernBertConfig(
        vocab_size=256,
        hidden_size=32,
        num_hidden_layers=2,
        num_attention_heads=2,
        intermediate_size=64,
        max_position_embeddings=64,
        pad_token_id=3,
        cls_token_id=1,
        sep_token_id=2,
        eos_token_id=None,
        bos_token_id=None,
    )


@pytest.fixture()
def tiny_encoder(tiny_modernbert_config):
    torch = pytest.importorskip("torch")
    from transformers import ModernBertModel

    torch.manual_seed(7)
    return ModernBertModel(tiny_modernbert_config)


@pytest.fixture()
def frozen_dataset_factory(tmp_path):
    """Build a sealed, contract-compliant frozen DOMAIN_ONLY dataset in a temp workspace."""

    def build(rows_per_class: int = 6, seed: int = 42, version: str = DATASET_VERSION):
        root = tmp_path / "workspace"
        splits_dir = root / "data" / "splits" / "domain_only"
        splits_dir.mkdir(parents=True, exist_ok=True)
        frames: dict[str, pd.DataFrame] = {}
        for split, offset in (("train", 0), ("validation", 100), ("test", 200)):
            rows = []
            for class_index, (label, prefix) in enumerate(
                (("BENIGN", "benign"), ("PHISHING", "phish"), ("MALWARE", "malware"))
            ):
                for index in range(rows_per_class):
                    domain = f"{prefix}-{split}-{offset + index}.example.test"
                    rows.append(
                        {
                            "label": label,
                            "source": f"{prefix}-source",
                            "registrable_domain": domain,
                            "model_url": f"https://{domain}/",
                            "normalized_url": f"https://{domain}/",
                            "hostname": domain,
                            "dataset_view": "DOMAIN_ONLY",
                            "collected_at": "2026-09-20",
                        }
                    )
            frame = pd.DataFrame(rows)
            frames[split] = frame
            frame.to_csv(splits_dir / f"{split}.csv", index=False, lineterminator="\n")

        manifest_path = root / "data" / "splits" / "test_manifest.json"
        candidate = build_test_manifest(version, {"domain_only": frames["test"]}, seed)
        seal_test_manifest(manifest_path, candidate)

        metadata_path = root / "data" / "processed" / "dataset_metadata.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(
                {
                    "datasetVersion": version,
                    "viewEligibility": {"domain_only": True, "full_url": False},
                }
            ),
            encoding="utf-8",
        )

        checkpoint_dir = root / "models" / "urlbert" / "domain_only" / "v1"
        config = {
            "urlbert": {
                "experiment_id": "URLBERT_DOMAIN_ONLY_V1_TEST",
                "model_name": "url_guardian_urlbert",
                "model_version": "0.4.0",
                "base_model": "CrabInHoney/urlbert-tiny-v6",
                "base_model_revision": "020744435b3be870dabb2bba0b41237bea69b84b",
                "dataset_version": version,
                "dataset_view": "domain_only",
                "dataset_metadata": str(metadata_path),
                "test_manifest": str(manifest_path),
                "expected_test_manifest_sha256": sha256_file(manifest_path),
                "expected_test_sha256": candidate["views"]["domain_only"]["sha256"],
                "splits_dir": str(splits_dir),
                "text_column": "registrable_domain",
                "label_mapping": LABEL_MAPPING,
                "pooling": "cls_mean",
                "head_hidden_size": 16,
                "head_dropout": 0.0,
                "max_length": 16,
                "training": {
                    "seed": 42,
                    "epochs": 1,
                    "batch_size": 4,
                    "batch_size_candidates": [4],
                    "learning_rate": 0.0001,
                    "weight_decay": 0.01,
                    "warmup_ratio": 0.1,
                    "scheduler": "linear",
                    "optimizer": "adamw",
                    "max_grad_norm": 1.0,
                    "early_stopping_metric": "macro_f1",
                    "early_stopping_patience": 1,
                    "mixed_precision": "off",
                    "gradient_accumulation_steps": 1,
                    "num_workers": 0,
                },
                "paths": {
                    "checkpoint_dir": str(checkpoint_dir),
                    "metrics": str(root / "reports" / "metrics" / "urlbert" / "domain_only"),
                    "figures": str(root / "reports" / "figures" / "urlbert" / "domain_only"),
                    "error_analysis": str(root / "reports" / "error_analysis" / "urlbert"),
                },
                "benchmark": {"warmup_iterations": 1, "timed_iterations": 3, "hardware_label": "test"},
            }
        }
        config_path = root / "urlbert.yaml"
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return {"root": root, "config_path": config_path, "frames": frames, "manifest": candidate}

    return build


@pytest.fixture()
def real_urlbert_tokenizer():
    transformers = pytest.importorskip("transformers")
    try:
        return transformers.AutoTokenizer.from_pretrained(
            "CrabInHoney/urlbert-tiny-v6",
            revision="020744435b3be870dabb2bba0b41237bea69b84b",
        )
    except Exception:  # pragma: no cover - environment dependent
        pytest.skip("URLBERT tokenizer is not available in this environment")
