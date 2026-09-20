"""UGDM (URL Guardian Decision Model) package.

Phase 2.6 defines the input and output contracts only. No UGDM model is trained
in this phase.
"""

from __future__ import annotations

from src.ugdm.schema import (
    ACTION_CLASSES,
    INPUT_SCHEMA_VERSION,
    OUTPUT_SCHEMA_VERSION,
    RISK_CLASSES,
    THREAT_CLASSES,
    UGDM_FEATURE_NAMES,
    UGDM_INPUT_GROUPS,
    UGDMInputSchema,
    UGDMOutputSchema,
    proposed_architecture_parameters,
    validate_feature_vector,
)

__all__ = [
    "ACTION_CLASSES",
    "INPUT_SCHEMA_VERSION",
    "OUTPUT_SCHEMA_VERSION",
    "RISK_CLASSES",
    "THREAT_CLASSES",
    "UGDM_FEATURE_NAMES",
    "UGDM_INPUT_GROUPS",
    "UGDMInputSchema",
    "UGDMOutputSchema",
    "proposed_architecture_parameters",
    "validate_feature_vector",
]
