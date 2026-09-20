"""UGDM (URL Guardian Decision Model) schemas.

Phase 2.6 does **not** train UGDM. It fixes the contract that the next phase will
implement: the structured input vector and the three output heads.

Design inspiration: structured probabilistic decision modelling in the spirit of
typed, multi-task decision models (System-One-like designs). This is an original
URL-security design, not a reproduction or clone of any specific system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

INPUT_SCHEMA_VERSION = 1
OUTPUT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FeatureGroup:
    """One named block of the UGDM input vector."""

    name: str
    features: tuple[str, ...]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.name,
            "featureCount": len(self.features),
            "features": list(self.features),
            "description": self.description,
        }


UGDM_INPUT_GROUPS: tuple[FeatureGroup, ...] = (
    FeatureGroup(
        name="urlbert",
        features=("phishing_probability", "benign_probability"),
        description="Calibrated output of the local URLBERT phishing model.",
    ),
    FeatureGroup(
        name="threat_intelligence",
        features=("known_malicious", "urlhaus_hit", "threatfox_hit"),
        description=(
            "Evidence from the Threat Intelligence layer. `known_malicious` is the merged status; "
            "the per-provider flags record which source matched. UNKNOWN must never be encoded as safe."
        ),
    ),
    FeatureGroup(
        name="url_structure",
        features=(
            "url_length",
            "hostname_length",
            "subdomain_count",
            "digit_ratio",
            "special_character_ratio",
            "hostname_entropy",
        ),
        description="Lexical and structural measurements of the URL string.",
    ),
    FeatureGroup(
        name="rules",
        features=(
            "has_ip",
            "has_punycode",
            "has_at_symbol",
            "uses_https",
            "has_non_default_port",
        ),
        description="Deterministic rule-based indicators.",
    ),
    FeatureGroup(
        name="keywords",
        features=(
            "contains_login",
            "contains_verify",
            "contains_secure",
            "contains_account",
            "contains_password",
            "contains_payment",
            "contains_wallet",
        ),
        description="Credential and payment themed keyword presence.",
    ),
    FeatureGroup(
        name="brand",
        features=("brand_detected", "brand_domain_mismatch", "brand_risk_score"),
        description="Brand impersonation signals computed locally from the domain string.",
    ),
    FeatureGroup(
        name="redirect",
        features=("redirect_count", "cross_domain_redirect", "shortener_detected"),
        description="Redirect context. Available only when the client can observe the chain.",
    ),
    FeatureGroup(
        name="local",
        features=("blacklist_hit", "whitelist_hit"),
        description="Local blacklist and whitelist decisions.",
    ),
)

UGDM_FEATURE_NAMES: tuple[str, ...] = tuple(
    feature for group in UGDM_INPUT_GROUPS for feature in group.features
)

RISK_CLASSES: tuple[str, ...] = ("SAFE", "SUSPICIOUS", "DANGEROUS")
ACTION_CLASSES: tuple[str, ...] = ("ALLOW", "REVIEW", "BLOCK")
THREAT_CLASSES: tuple[str, ...] = ("BENIGN", "PHISHING", "KNOWN_MALWARE", "OTHER")

UGDM_OUTPUT_HEADS: dict[str, tuple[str, ...]] = {
    "risk": RISK_CLASSES,
    "action": ACTION_CLASSES,
    "threat": THREAT_CLASSES,
}


def feature_index() -> dict[str, int]:
    return {name: index for index, name in enumerate(UGDM_FEATURE_NAMES)}


def validate_feature_vector(values: dict[str, Any]) -> list[str]:
    """Return the list of contract violations for one candidate input vector."""

    problems: list[str] = []
    expected = set(UGDM_FEATURE_NAMES)
    provided = set(values)
    for missing in sorted(expected - provided):
        problems.append(f"missing feature: {missing}")
    for extra in sorted(provided - expected):
        problems.append(f"unexpected feature: {extra}")
    for name, value in values.items():
        if name not in expected:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            continue
        problems.append(f"feature {name} must be numeric or boolean, got {type(value).__name__}")
    return problems


@dataclass(frozen=True)
class UGDMInputSchema:
    """Frozen description of the UGDM input contract."""

    version: int = INPUT_SCHEMA_VERSION
    groups: tuple[FeatureGroup, ...] = UGDM_INPUT_GROUPS

    @property
    def feature_names(self) -> tuple[str, ...]:
        return tuple(feature for group in self.groups for feature in group.features)

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.version,
            "featureCount": self.feature_count,
            "groups": [group.to_dict() for group in self.groups],
            "forbiddenInputs": [
                "raw HTML",
                "cookies",
                "passwords or form contents",
                "browser history",
                "provider identity or source name as a feature",
            ],
            "threatIntelligenceRule": (
                "UNKNOWN means the intelligence sources did not contain the indicator. It must never "
                "be encoded as safe, and UNAVAILABLE/ERROR must be encoded separately from UNKNOWN."
            ),
        }


@dataclass(frozen=True)
class UGDMOutputSchema:
    """Frozen description of the UGDM multi-task output contract."""

    version: int = OUTPUT_SCHEMA_VERSION
    heads: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(UGDM_OUTPUT_HEADS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.version,
            "heads": {
                name: {"classes": list(classes), "classCount": len(classes)}
                for name, classes in self.heads.items()
            },
            "threatHeadRule": (
                "KNOWN_MALWARE is supported by Threat Intelligence evidence. UGDM must not predict "
                "KNOWN_MALWARE for a domain that no intelligence source has recorded."
            ),
            "actionHeadRule": (
                "The action head must not emit BLOCK without either a Threat Intelligence hit or a "
                "high-risk model decision with a documented threshold."
            ),
        }


def proposed_architecture_parameters(
    input_dim: int | None = None,
    hidden_sizes: tuple[int, int, int] = (128, 128, 64),
) -> dict[str, Any]:
    """Parameter budget for the proposed shared-trunk multi-task network.

    Layout: structured features -> normalisation -> Dense 128 -> GELU -> Dropout
    -> Dense 128 -> GELU -> Dense 64 shared representation -> three heads.
    """

    dims = (input_dim if input_dim is not None else len(UGDM_FEATURE_NAMES), *hidden_sizes)
    trunk = 0
    for previous, current in zip(dims, dims[1:]):
        trunk += previous * current + current
    head_parameters = 0
    head_details: dict[str, int] = {}
    for name, classes in UGDM_OUTPUT_HEADS.items():
        count = dims[-1] * len(classes) + len(classes)
        head_details[name] = count
        head_parameters += count
    total = trunk + head_parameters
    return {
        "inputDim": dims[0],
        "hiddenSizes": list(hidden_sizes),
        "trunkParameters": trunk,
        "headParameters": head_details,
        "totalParameters": total,
        "targetUnder": 1_000_000,
        "meetsTarget": total < 1_000_000,
        "deploymentNote": "Small enough for ONNX export and on-device inference in a later phase.",
    }
