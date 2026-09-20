"""Configuration loading for the Phase 2 URLBERT experiment."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.utils.config import PROJECT_ROOT

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "urlbert.yaml"


class URLBERTConfigError(ValueError):
    """Raised when the URLBERT configuration is missing or inconsistent."""


@dataclass(frozen=True)
class URLBERTConfig:
    """Typed view over `configs/urlbert.yaml`."""

    raw: dict[str, Any]
    config_path: Path

    @property
    def experiment_id(self) -> str:
        return str(self.raw["experiment_id"])

    @property
    def base_model(self) -> str:
        return str(self.raw["base_model"])

    @property
    def base_model_revision(self) -> str:
        return str(self.raw["base_model_revision"])

    @property
    def dataset_version(self) -> str:
        return str(self.raw["dataset_version"])

    @property
    def dataset_view(self) -> str:
        return str(self.raw["dataset_view"])

    @property
    def max_length(self) -> int:
        return int(self.raw["max_length"])

    @property
    def pooling(self) -> str:
        return str(self.raw["pooling"])

    @property
    def head_hidden_size(self) -> int:
        return int(self.raw["head_hidden_size"])

    @property
    def head_dropout(self) -> float:
        return float(self.raw["head_dropout"])

    @property
    def text_column(self) -> str:
        return str(self.raw["text_column"])

    @property
    def manifest_view(self) -> str:
        """Key used inside the Test Manifest.

        Phase 2 sealed the manifest by dataset view (`domain_only`). Phase 2.5
        seals it by sampling regime (`artifact_controlled`, `natural`), so the
        manifest key is configurable while the model text stays DOMAIN_ONLY.
        """

        return str(self.raw.get("test_manifest_view", self.dataset_view))

    @property
    def label_mapping(self) -> dict[str, int]:
        return {str(key): int(value) for key, value in self.raw["label_mapping"].items()}

    @property
    def num_classes(self) -> int:
        return len(self.label_mapping)

    @property
    def label_names(self) -> list[str]:
        """Class names ordered by their integer label."""

        return [name for name, _ in sorted(self.label_mapping.items(), key=lambda item: item[1])]

    @property
    def seed(self) -> int:
        return int(self.raw["training"]["seed"])

    @property
    def epochs(self) -> int:
        return int(self.raw["training"]["epochs"])

    @property
    def training(self) -> dict[str, Any]:
        return dict(self.raw["training"])

    @property
    def benchmark(self) -> dict[str, Any]:
        return dict(self.raw.get("benchmark", {}))

    @property
    def splits_dir(self) -> Path:
        return self.raw_path("splits_dir")

    def path(self, key: str) -> Path:
        value = self.raw["paths"][key]
        path = Path(str(value))
        return path if path.is_absolute() else PROJECT_ROOT / path

    def raw_path(self, key: str) -> Path:
        value = self.raw[key]
        path = Path(str(value))
        return path if path.is_absolute() else PROJECT_ROOT / path


def load_urlbert_config(config_path: str | Path | None = None) -> URLBERTConfig:
    """Load and validate the URLBERT experiment configuration."""

    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.exists():
        raise URLBERTConfigError(f"URLBERT config not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict) or "urlbert" not in payload:
        raise URLBERTConfigError(f"URLBERT config must contain a top-level 'urlbert' mapping: {path}")
    raw = payload["urlbert"]
    required = {
        "experiment_id",
        "base_model",
        "base_model_revision",
        "dataset_version",
        "dataset_view",
        "test_manifest",
        "splits_dir",
        "text_column",
        "label_mapping",
        "max_length",
        "training",
        "paths",
    }
    missing = sorted(required.difference(raw))
    if missing:
        raise URLBERTConfigError(f"URLBERT config is missing keys: {missing}")
    if raw["dataset_view"] != "domain_only":
        raise URLBERTConfigError("Phase 2 URLBERT is restricted to the DOMAIN_ONLY view")
    label_values = sorted(int(value) for value in raw["label_mapping"].values())
    if label_values not in ([0, 1, 2], [0, 1]):
        raise URLBERTConfigError("URLBERT label mapping must map either two or three classes to 0..n")
    if int(raw["max_length"]) <= 0:
        raise URLBERTConfigError("URLBERT max_length must be positive")
    return URLBERTConfig(raw=raw, config_path=path)
