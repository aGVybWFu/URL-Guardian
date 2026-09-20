"""UGDM (URL Guardian Decision Model) package."""

from __future__ import annotations

from src.models.ugdm.model import (
    ARCHITECTURE_VERSION,
    UGDM,
    architecture_summary,
    encode_inputs,
    fit_normalizer,
)

__all__ = [
    "ARCHITECTURE_VERSION",
    "UGDM",
    "architecture_summary",
    "encode_inputs",
    "fit_normalizer",
]
