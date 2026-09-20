"""UGDM schema tests plus immutability and safety guards for Phase 2.6."""

import json
from pathlib import Path

import pytest

from src.ugdm import (
    ACTION_CLASSES,
    RISK_CLASSES,
    THREAT_CLASSES,
    UGDM_FEATURE_NAMES,
    UGDM_INPUT_GROUPS,
    UGDMInputSchema,
    UGDMOutputSchema,
    proposed_architecture_parameters,
    validate_feature_vector,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_ugdm_feature_schema_covers_every_planned_group():
    schema = UGDMInputSchema()
    groups = {group.name for group in schema.groups}
    assert groups == {
        "urlbert",
        "threat_intelligence",
        "url_structure",
        "rules",
        "keywords",
        "brand",
        "redirect",
        "local",
    }
    assert schema.feature_count == len(UGDM_FEATURE_NAMES)
    assert schema.feature_count == 31


def test_ugdm_feature_schema_lists_required_individual_features():
    names = set(UGDM_FEATURE_NAMES)
    for required in (
        "phishing_probability",
        "benign_probability",
        "known_malicious",
        "urlhaus_hit",
        "threatfox_hit",
        "url_length",
        "hostname_entropy",
        "has_ip",
        "has_punycode",
        "contains_login",
        "brand_detected",
        "brand_domain_mismatch",
        "redirect_count",
        "blacklist_hit",
        "whitelist_hit",
    ):
        assert required in names, required


def test_ugdm_feature_schema_forbids_provider_identity_as_a_feature():
    names = {name.lower() for name in UGDM_FEATURE_NAMES}
    for forbidden in ("source", "provider", "reporter", "feed", "label"):
        assert forbidden not in names


def test_ugdm_output_schema_defines_three_heads():
    schema = UGDMOutputSchema()
    assert schema.heads["risk"] == RISK_CLASSES == ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert schema.heads["action"] == ACTION_CLASSES == ("ALLOW", "REVIEW", "BLOCK")
    assert schema.heads["threat"] == THREAT_CLASSES == ("BENIGN", "PHISHING", "KNOWN_MALWARE", "OTHER")
    payload = schema.to_dict()
    assert "Threat Intelligence evidence" in payload["threatHeadRule"]
    assert "BLOCK" in payload["actionHeadRule"]


def test_ugdm_input_schema_records_the_unknown_not_safe_rule():
    payload = UGDMInputSchema().to_dict()
    assert "never" in payload["threatIntelligenceRule"].lower()
    assert "UNKNOWN" in payload["threatIntelligenceRule"]
    assert any("raw HTML" in value for value in payload["forbiddenInputs"])
    assert any("cookies" in value for value in payload["forbiddenInputs"])


def test_ugdm_architecture_stays_under_the_parameter_target():
    budget = proposed_architecture_parameters()
    assert budget["meetsTarget"] is True
    assert budget["totalParameters"] < 1_000_000
    assert budget["inputDim"] == 31


def test_feature_vector_validator_accepts_a_complete_vector_and_rejects_gaps():
    complete = {name: 0.0 for name in UGDM_FEATURE_NAMES}
    assert validate_feature_vector(complete) == []
    incomplete = dict(complete)
    incomplete.pop("phishing_probability")
    problems = validate_feature_vector(incomplete)
    assert any("missing feature: phishing_probability" in problem for problem in problems)
    extra = dict(complete, source_flag=1.0)
    assert any("unexpected feature" in problem for problem in validate_feature_vector(extra))
    bad_type = dict(complete, url_length="long")
    assert any("must be numeric" in problem for problem in validate_feature_vector(bad_type))


def test_ugdm_is_documented_as_not_trained_in_this_phase():
    source = (REPO_ROOT / "src" / "ugdm" / "__init__.py").read_text(encoding="utf-8")
    assert "No UGDM model is trained" in source
    design = REPO_ROOT / "docs" / "14_ugdm_design.md"
    if design.exists():
        text = design.read_text(encoding="utf-8").replace("**", "").lower()
        assert "not" in text
        assert "a reproduction" in text or "a clone" in text
        assert "design only" in text
        assert "does not train ugdm" in text or "does not train" in text


def test_previous_dataset_versions_are_immutable():
    from src.data.snapshot import sha256_file

    legacy_manifest = REPO_ROOT / "data" / "splits" / "test_manifest.json"
    v12_manifest = REPO_ROOT / "data" / "splits" / "v1.2.0" / "test_manifest_v1.2.0.json"
    if not legacy_manifest.exists() or not v12_manifest.exists():
        pytest.skip("older dataset versions are not present in this environment")
    assert sha256_file(legacy_manifest) == (
        "21b7b7284f5d207beb4d4d673fc0471e38e92fef0a15d278710ff5bedd596e20"
    )
    assert sha256_file(v12_manifest) == (
        "ca31fcd2a1be7828fb0f5afff91b55b9219d2ec5f0ff621d1e5ed12c8c2c0322"
    )


def test_previous_dataset_metadata_is_untouched():
    for relative, version in (
        ("data/processed/metadata/dataset-v1.0.0.json", "dataset-v1.0.0"),
        ("data/processed/v1.2.0/dataset_metadata.json", "dataset-v1.2.0"),
    ):
        path = REPO_ROOT / relative
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["datasetVersion"] == version


def test_threat_intelligence_source_never_requests_a_dataset_url():
    for relative in (
        "src/threat_intel/contract.py",
        "src/threat_intel/providers.py",
        "src/threat_intel/__init__.py",
    ):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for token in ("requests.get(", "requests.post(", "socket.connect(", "urlopen(", "playwright", "selenium"):
            assert token not in text, (relative, token)


def test_binary_pipeline_never_requests_a_dataset_url():
    for relative in (
        "src/models/lightgbm_binary.py",
        "src/evaluation/phase26.py",
        "src/data/dataset_v13.py",
    ):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for token in ("requests.get(", "requests.post(", "socket.connect(", "urlopen(", "playwright", "selenium"):
            assert token not in text, (relative, token)
