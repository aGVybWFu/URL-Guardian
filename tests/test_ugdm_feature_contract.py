"""UGDM feature schema, availability mask and normalizer contract tests."""

import json
from pathlib import Path

import numpy as np
import pytest

from src.ugdm.features import (
    AVAILABILITY_ALWAYS,
    AVAILABILITY_MASK_DIMENSION,
    AVAILABILITY_NOT_IMPLEMENTED,
    FEATURE_SPEC_BY_NAME,
    UGDMFeatureAvailabilityMask,
    default_availability,
    feature_spec_payload,
    validate_feature_specs,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES, UGDMInputSchema, UGDMOutputSchema

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FEATURES = (
    "phishing_probability",
    "benign_probability",
    "known_malicious",
    "urlhaus_hit",
    "threatfox_hit",
    "url_length",
    "hostname_length",
    "subdomain_count",
    "digit_ratio",
    "special_character_ratio",
    "hostname_entropy",
    "has_ip",
    "has_punycode",
    "has_at_symbol",
    "uses_https",
    "has_non_default_port",
    "contains_login",
    "contains_verify",
    "contains_secure",
    "contains_account",
    "contains_password",
    "contains_payment",
    "contains_wallet",
    "brand_detected",
    "brand_domain_mismatch",
    "brand_risk_score",
    "redirect_count",
    "cross_domain_redirect",
    "shortener_detected",
    "blacklist_hit",
    "whitelist_hit",
)


def test_feature_order_is_frozen():
    assert tuple(UGDM_FEATURE_NAMES) == EXPECTED_FEATURES
    assert len(UGDM_FEATURE_NAMES) == 31


def test_feature_specs_match_the_frozen_schema():
    assert validate_feature_specs() == []
    payload = feature_spec_payload()
    assert payload["featureCount"] == 31
    assert payload["availabilityMaskDimension"] == 31
    assert payload["modelInputDimension"] == 62


def test_every_feature_spec_has_the_required_fields():
    for spec in FEATURE_SPEC_BY_NAME.values():
        assert spec.dtype in {"float", "bool"}
        assert spec.minimum <= spec.maximum
        assert spec.normalization in {"zscore", "identity"}
        assert spec.availability in {
            AVAILABILITY_ALWAYS,
            "CONDITIONAL",
            AVAILABILITY_NOT_IMPLEMENTED,
        }
        assert spec.source


def test_unimplemented_features_are_declared_not_faked():
    unimplemented = {
        name for name, spec in FEATURE_SPEC_BY_NAME.items()
        if spec.availability == AVAILABILITY_NOT_IMPLEMENTED
    }
    assert unimplemented == {
        "brand_detected",
        "brand_domain_mismatch",
        "brand_risk_score",
        "redirect_count",
        "cross_domain_redirect",
        "shortener_detected",
        "blacklist_hit",
        "whitelist_hit",
    }


def test_availability_mask_dimension_and_values():
    mask = UGDMFeatureAvailabilityMask.from_spec_defaults()
    assert mask.dimension == AVAILABILITY_MASK_DIMENSION == 31
    assert len(mask.available_features()) == 23
    assert mask.available("phishing_probability") is True
    assert mask.available("brand_detected") is False
    with pytest.raises(ValueError):
        UGDMFeatureAvailabilityMask(tuple([0] * 30))
    with pytest.raises(ValueError):
        UGDMFeatureAvailabilityMask(tuple([2] * 31))


def test_threat_intel_availability_tracks_provider_health():
    without = UGDMFeatureAvailabilityMask.from_availability(default_availability({}))
    assert without.available("known_malicious") is False
    assert without.available("phishing_probability") is True
    with_provider = UGDMFeatureAvailabilityMask.from_availability(
        default_availability({"URLHAUS": "AVAILABLE", "THREATFOX": "UNAVAILABLE"})
    )
    assert with_provider.available("known_malicious") is True
    unavailable = UGDMFeatureAvailabilityMask.from_availability(
        default_availability({"URLHAUS": "UNAVAILABLE", "THREATFOX": "UNAVAILABLE"})
    )
    assert unavailable.available("known_malicious") is False


def test_zero_value_is_distinguished_from_missing_by_the_mask():
    from src.models.ugdm.model import encode_inputs, fit_normalizer

    normalizer = fit_normalizer([{"url_length": 10.0}])
    values = {name: 0.0 for name in UGDM_FEATURE_NAMES}
    present = encode_inputs(values, {name: True for name in UGDM_FEATURE_NAMES}, normalizer)
    absent = encode_inputs(values, {name: False for name in UGDM_FEATURE_NAMES}, normalizer)
    assert present.shape == absent.shape == (62,)
    assert not np.allclose(present, absent)
    # The mask half differs, so "measured zero" and "no data" are distinguishable.
    assert not np.array_equal(present[31:], absent[31:])


def test_normalizer_is_fitted_on_train_only():
    from src.models.ugdm.evaluate import load_dataset, split_frame
    from src.models.ugdm.model import fit_normalizer
    from src.models.ugdm.train import _row_values

    dataset = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset.csv"
    if not dataset.exists():
        pytest.skip("ugdm-dataset-v1.0.0 is not built in this environment")
    frame, _ = load_dataset()
    train_frame = split_frame(frame, "train")
    test_frame = split_frame(frame, "test")
    train_normalizer = fit_normalizer(_row_values(train_frame))
    test_normalizer = fit_normalizer(_row_values(test_frame))
    assert train_normalizer.fitted_on == "train"
    assert train_normalizer.mean["url_length"] != test_normalizer.mean["url_length"]
    source = (REPO_ROOT / "src" / "models" / "ugdm" / "train.py").read_text(encoding="utf-8")
    assert "normalizer = fit_normalizer(_row_values(train_frame))" in source


def test_output_schema_heads_are_unchanged():
    heads = UGDMOutputSchema().heads
    assert heads["risk"] == ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert heads["action"] == ("ALLOW", "REVIEW", "BLOCK")
    assert heads["threat"] == ("BENIGN", "PHISHING", "KNOWN_MALWARE", "OTHER")
    assert UGDMInputSchema().feature_count == 31
