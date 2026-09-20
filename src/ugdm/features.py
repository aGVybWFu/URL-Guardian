"""UGDM feature specification and availability contract.

The 31 features of `UGDMInputSchema` v1 are frozen. This module adds the
machine-readable detail the model needs: data type, expected range,
normalization method, availability rule and provenance.

Availability is separate from value. A feature that is not implemented must
report `availability = 0` rather than a fabricated `0.0` value that would be
indistinguishable from "measured, and there is no risk".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.ugdm.schema import UGDM_FEATURE_NAMES, UGDM_INPUT_GROUPS

AVAILABILITY_ALWAYS = "ALWAYS"
AVAILABILITY_CONDITIONAL = "CONDITIONAL"
AVAILABILITY_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

NORMALIZATION_ZSCORE = "zscore"
NORMALIZATION_IDENTITY = "identity"

DTYPE_FLOAT = "float"
DTYPE_BOOL = "bool"


@dataclass(frozen=True)
class UGDMFeatureSpec:
    """Machine-readable contract for one UGDM input feature."""

    name: str
    group: str
    dtype: str
    minimum: float
    maximum: float
    normalization: str
    availability: str
    source: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "group": self.group,
            "dtype": self.dtype,
            "expectedRange": [self.minimum, self.maximum],
            "normalization": self.normalization,
            "availability": self.availability,
            "source": self.source,
            "notes": self.notes,
        }


def _spec(
    name: str,
    group: str,
    dtype: str,
    minimum: float,
    maximum: float,
    normalization: str,
    availability: str,
    source: str,
    notes: str = "",
) -> UGDMFeatureSpec:
    return UGDMFeatureSpec(
        name=name,
        group=group,
        dtype=dtype,
        minimum=minimum,
        maximum=maximum,
        normalization=normalization,
        availability=availability,
        source=source,
        notes=notes,
    )


UGDM_FEATURE_SPECS: tuple[UGDMFeatureSpec, ...] = (
    # urlbert probabilities (available: the binary URLBERT artifact produces them)
    _spec("phishing_probability", "urlbert", DTYPE_FLOAT, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "URLBERT_PHISHING_BINARY_V1 softmax output", "Selected probability version is recorded in metadata."),
    _spec("benign_probability", "urlbert", DTYPE_FLOAT, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "URLBERT_PHISHING_BINARY_V1 softmax output", "Complement of the phishing probability."),
    # threat intelligence (available while at least one provider is AVAILABLE)
    _spec("known_malicious", "threat_intelligence", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_CONDITIONAL,
          "ThreatIntelligenceService merged status",
          "1 only for a confirmed KNOWN_MALICIOUS match. UNKNOWN is never encoded as safe."),
    _spec("urlhaus_hit", "threat_intelligence", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_CONDITIONAL,
          "UrlHausProvider", "Per-provider evidence flag."),
    _spec("threatfox_hit", "threat_intelligence", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_CONDITIONAL,
          "ThreatFoxProvider", "Per-provider evidence flag."),
    # url structure (always available from the URL string)
    _spec("url_length", "url_structure", DTYPE_FLOAT, 0.0, 4096.0, NORMALIZATION_ZSCORE, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("hostname_length", "url_structure", DTYPE_FLOAT, 0.0, 253.0, NORMALIZATION_ZSCORE, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("subdomain_count", "url_structure", DTYPE_FLOAT, 0.0, 32.0, NORMALIZATION_ZSCORE, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("digit_ratio", "url_structure", DTYPE_FLOAT, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("special_character_ratio", "url_structure", DTYPE_FLOAT, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("hostname_entropy", "url_structure", DTYPE_FLOAT, 0.0, 8.0, NORMALIZATION_ZSCORE, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    # deterministic rules (always available)
    _spec("has_ip", "rules", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("has_punycode", "rules", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("has_at_symbol", "rules", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("uses_https", "rules", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("has_non_default_port", "rules", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    # credential and payment keywords (always available)
    _spec("contains_login", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_verify", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_secure", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_account", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_password", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_payment", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    _spec("contains_wallet", "keywords", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_ALWAYS,
          "src.features.extractor"),
    # brand impersonation: not implemented in Phase 3 v1
    _spec("brand_detected", "brand", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Placeholder. Availability is 0 until a brand detector exists."),
    _spec("brand_domain_mismatch", "brand", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Placeholder. Availability is 0 until a brand detector exists."),
    _spec("brand_risk_score", "brand", DTYPE_FLOAT, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Placeholder. Availability is 0 until a brand detector exists."),
    # redirect context: requires observing the redirect chain
    _spec("redirect_count", "redirect", DTYPE_FLOAT, 0.0, 32.0, NORMALIZATION_ZSCORE, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Requires observing the redirect chain, which static URL analysis cannot do."),
    _spec("cross_domain_redirect", "redirect", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Requires observing the redirect chain."),
    _spec("shortener_detected", "redirect", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "Requires a maintained shortener list; none is approved yet."),
    # local lists: no approved local list exists
    _spec("blacklist_hit", "local", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "No approved on-device blacklist exists yet."),
    _spec("whitelist_hit", "local", DTYPE_BOOL, 0.0, 1.0, NORMALIZATION_IDENTITY, AVAILABILITY_NOT_IMPLEMENTED,
          "not implemented", "No approved on-device whitelist exists yet."),
)

FEATURE_SPEC_BY_NAME: dict[str, UGDMFeatureSpec] = {spec.name: spec for spec in UGDM_FEATURE_SPECS}
AVAILABILITY_MASK_DIMENSION = len(UGDM_FEATURE_SPECS)


def validate_feature_specs() -> list[str]:
    """Check the spec table against the frozen schema and the group definitions."""

    problems: list[str] = []
    if tuple(spec.name for spec in UGDM_FEATURE_SPECS) != tuple(UGDM_FEATURE_NAMES):
        problems.append("feature spec order does not match UGDM_FEATURE_NAMES")
    group_members = {group.name: list(group.features) for group in UGDM_INPUT_GROUPS}
    for group_name, members in group_members.items():
        for name in members:
            spec = FEATURE_SPEC_BY_NAME.get(name)
            if spec is None:
                problems.append(f"missing feature spec: {name}")
            elif spec.group != group_name:
                problems.append(f"feature {name} is declared in group {spec.group}, expected {group_name}")
    for spec in UGDM_FEATURE_SPECS:
        if spec.dtype not in {DTYPE_FLOAT, DTYPE_BOOL}:
            problems.append(f"feature {spec.name} has an unknown dtype: {spec.dtype}")
        if spec.minimum > spec.maximum:
            problems.append(f"feature {spec.name} has an inverted range")
        if spec.availability not in {
            AVAILABILITY_ALWAYS,
            AVAILABILITY_CONDITIONAL,
            AVAILABILITY_NOT_IMPLEMENTED,
        }:
            problems.append(f"feature {spec.name} has an unknown availability: {spec.availability}")
    return problems


@dataclass(frozen=True)
class UGDMFeatureAvailabilityMask:
    """Availability flags for one UGDM input row.

    The mask is a separate vector so that `0.0` never has to mean both "measured
    as no risk" and "no data". A `0` flag means the value must be ignored.
    """

    flags: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.flags) != AVAILABILITY_MASK_DIMENSION:
            raise ValueError(
                f"availability mask must have {AVAILABILITY_MASK_DIMENSION} entries, got {len(self.flags)}"
            )
        if any(flag not in (0, 1) for flag in self.flags):
            raise ValueError("availability mask entries must be 0 or 1")

    @property
    def dimension(self) -> int:
        return len(self.flags)

    def available(self, feature_name: str) -> bool:
        index = UGDM_FEATURE_NAMES.index(feature_name)
        return bool(self.flags[index])

    def available_features(self) -> list[str]:
        return [name for name, flag in zip(UGDM_FEATURE_NAMES, self.flags) if flag]

    def unavailable_features(self) -> list[str]:
        return [name for name, flag in zip(UGDM_FEATURE_NAMES, self.flags) if not flag]

    def to_list(self) -> list[int]:
        return list(self.flags)

    @classmethod
    def from_availability(cls, availability: dict[str, bool]) -> "UGDMFeatureAvailabilityMask":
        return cls(tuple(1 if availability.get(name, False) else 0 for name in UGDM_FEATURE_NAMES))

    @classmethod
    def from_spec_defaults(cls) -> "UGDMFeatureAvailabilityMask":
        return cls(
            tuple(0 if spec.availability == AVAILABILITY_NOT_IMPLEMENTED else 1 for spec in UGDM_FEATURE_SPECS)
        )


def default_availability(provider_status: dict[str, str] | None = None) -> dict[str, bool]:
    """Availability for one inference row.

    `provider_status` maps provider names to `AVAILABLE` / `UNAVAILABLE`. Threat
    intelligence features are only available when at least one provider is up,
    because an unavailable provider means "no data", not "no threat".
    """

    availability = {
        spec.name: spec.availability == AVAILABILITY_ALWAYS for spec in UGDM_FEATURE_SPECS
    }
    threat_intel_available = bool(provider_status) and any(
        status == "AVAILABLE" for status in (provider_status or {}).values()
    )
    for name in ("known_malicious", "urlhaus_hit", "threatfox_hit"):
        availability[name] = threat_intel_available
    return availability


def feature_spec_payload() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "featureCount": len(UGDM_FEATURE_SPECS),
        "availabilityMaskDimension": AVAILABILITY_MASK_DIMENSION,
        "modelInputDimension": len(UGDM_FEATURE_SPECS) * 2,
        "features": [spec.to_dict() for spec in UGDM_FEATURE_SPECS],
        "missingnessContract": (
            "Values and availability are separate vectors. A feature with availability 0 must be "
            "ignored by the model; its value carries no meaning and is never interpreted as safe."
        ),
    }
