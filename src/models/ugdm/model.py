"""UGDM network, input normalisation and availability-mask handling.

UGDM consumes structured security evidence only: URLBERT probabilities, Threat
Intelligence flags, URL structure, rules and keywords. It never sees raw URL
text, HTML, cookies or form contents.

Input layout is `[values (31), availability mask (31)]` = 62 dimensions, so a
missing feature can never be confused with a measured zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
from torch import nn

from src.ugdm.features import (
    AVAILABILITY_MASK_DIMENSION,
    NORMALIZATION_ZSCORE,
    UGDM_FEATURE_SPECS,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES

ARCHITECTURE_VERSION = "UGDM-v1"
FEATURE_SCHEMA_VERSION = 1
OUTPUT_SCHEMA_VERSION = 1
HIDDEN_SIZES: tuple[int, int, int] = (128, 128, 64)
DROPOUT = 0.1
NUM_RISK = 3
NUM_ACTION = 3
NUM_THREAT = 4


@dataclass(frozen=True)
class Normalizer:
    """Train-only z-score statistics for the continuous features."""

    feature_names: tuple[str, ...]
    mean: dict[str, float]
    std: dict[str, float]
    fitted_on: str = "train"

    def transform(self, name: str, value: float) -> float:
        if name not in self.mean:
            return float(value)
        std = self.std.get(name, 1.0)
        if std <= 0:
            return 0.0
        return (float(value) - self.mean[name]) / std

    def to_dict(self) -> dict[str, Any]:
        return {
            "fittedOn": self.fitted_on,
            "method": "zscore",
            "features": list(self.feature_names),
            "mean": self.mean,
            "std": self.std,
        }


def fit_normalizer(rows: list[dict[str, float]]) -> Normalizer:
    """Fit z-score statistics on Train rows only."""

    zscore_features = [
        spec.name for spec in UGDM_FEATURE_SPECS if spec.normalization == NORMALIZATION_ZSCORE
    ]
    mean: dict[str, float] = {}
    std: dict[str, float] = {}
    for name in zscore_features:
        values = np.array([float(row.get(name, 0.0)) for row in rows], dtype=float)
        mean[name] = float(values.mean()) if values.size else 0.0
        deviation = float(values.std(ddof=0)) if values.size else 0.0
        std[name] = deviation if deviation > 1e-12 else 1.0
    return Normalizer(feature_names=tuple(zscore_features), mean=mean, std=std)


def encode_inputs(
    values: dict[str, float],
    availability: dict[str, bool],
    normalizer: Normalizer,
) -> np.ndarray:
    """Build the 62-dimensional model input for one row."""

    vector = np.zeros(2 * len(UGDM_FEATURE_NAMES), dtype=np.float32)
    for index, name in enumerate(UGDM_FEATURE_NAMES):
        available = bool(availability.get(name, False))
        raw = float(values.get(name, 0.0)) if available else 0.0
        vector[index] = normalizer.transform(name, raw) if available else 0.0
        vector[len(UGDM_FEATURE_NAMES) + index] = 1.0 if available else 0.0
    return vector


class UGDM(nn.Module):
    """Shared-trunk multi-task decision network with three heads."""

    def __init__(
        self,
        input_dim: int | None = None,
        hidden_sizes: tuple[int, int, int] = HIDDEN_SIZES,
        dropout: float = DROPOUT,
    ) -> None:
        super().__init__()
        self.input_dim = int(input_dim or 2 * len(UGDM_FEATURE_NAMES))
        first, second, third = hidden_sizes
        self.trunk = nn.Sequential(
            nn.Linear(self.input_dim, first),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(first, second),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(second, third),
            nn.GELU(),
        )
        self.risk_head = nn.Linear(third, NUM_RISK)
        self.action_head = nn.Linear(third, NUM_ACTION)
        self.threat_head = nn.Linear(third, NUM_THREAT)

    def forward(self, inputs: torch.Tensor) -> dict[str, torch.Tensor]:
        shared = self.trunk(inputs)
        return {
            "risk": self.risk_head(shared),
            "action": self.action_head(shared),
            "threat": self.threat_head(shared),
        }

    def probabilities(self, inputs: torch.Tensor) -> dict[str, torch.Tensor]:
        """Softmax probabilities per head. Uncalibrated by construction."""

        logits = self.forward(inputs)
        return {name: torch.softmax(value, dim=-1) for name, value in logits.items()}

    def parameter_count(self) -> int:
        return int(sum(parameter.numel() for parameter in self.parameters()))


def architecture_summary() -> dict[str, Any]:
    model = UGDM()
    return {
        "architectureVersion": ARCHITECTURE_VERSION,
        "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "featureCount": len(UGDM_FEATURE_NAMES),
        "availabilityMaskDimension": AVAILABILITY_MASK_DIMENSION,
        "inputDimension": model.input_dim,
        "hiddenSizes": list(HIDDEN_SIZES),
        "dropout": DROPOUT,
        "heads": {"risk": NUM_RISK, "action": NUM_ACTION, "threat": NUM_THREAT},
        "parameterCount": model.parameter_count(),
        "underParameterTarget": model.parameter_count() < 100_000,
    }
