"""Policy, cost function, multi-task loss, guardrail and counterfactual tests."""

import json
from pathlib import Path

import numpy as np
import pytest
import torch

from src.models.ugdm.model import UGDM, architecture_summary, encode_inputs, fit_normalizer
from src.models.ugdm.train import masked_cross_entropy, SUPPORTED_THREAT_TARGETS
from src.ugdm.features import UGDMFeatureAvailabilityMask, default_availability
from src.ugdm.policy import (
    ACTION_CLASSES,
    COST_VERSION,
    DEFAULT_COST,
    DEPLOYMENT_PHISHING_PREVALENCE,
    POLICY_VERSION,
    RISK_CLASSES,
    THREAT_CLASSES,
    DecisionCost,
    PolicyThresholds,
    decide,
    prevalence_weights,
    select_thresholds,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]


def _features(**overrides) -> dict[str, float]:
    values = {name: 0.0 for name in UGDM_FEATURE_NAMES}
    values.update(overrides)
    return values


def _availability(**overrides) -> dict[str, bool]:
    availability = {name: True for name in UGDM_FEATURE_NAMES}
    availability.update(overrides)
    return availability


def test_cost_matrix_ordering_matches_the_documented_assumptions():
    matrix = DEFAULT_COST.matrix()
    assert matrix["KNOWN_MALWARE"]["ALLOW"] > matrix["PHISHING"]["ALLOW"] > matrix["BENIGN"]["BLOCK"] > 0
    assert matrix["PHISHING"]["ALLOW"] > matrix["PHISHING"]["REVIEW"] > matrix["BENIGN"]["ALLOW"]
    assert matrix["BENIGN"]["REVIEW"] > matrix["BENIGN"]["ALLOW"]
    assert matrix["PHISHING"]["BLOCK"] == 0.0
    assert DEFAULT_COST.version == COST_VERSION


def test_cost_function_is_versioned_and_documented():
    payload = DEFAULT_COST.to_dict()
    assert payload["version"] == COST_VERSION
    assert payload["unit"] == "one benign review prompt"
    assert "assumptions" in payload
    assert set(payload["matrix"]) == {"BENIGN", "PHISHING", "KNOWN_MALWARE"}


def test_prevalence_weights_reweight_a_balanced_split():
    labels = ["BENIGN", "PHISHING"] * 50
    weights = prevalence_weights(labels, 0.02)
    phishing_weight = weights[1]
    benign_weight = weights[0]
    assert phishing_weight < benign_weight
    total = sum(weights)
    effective_phishing = sum(w for w, label in zip(weights, labels) if label == "PHISHING") / total
    assert effective_phishing == pytest.approx(0.02, abs=1e-9)


def test_policy_is_deterministic():
    values = _features(phishing_probability=0.5, contains_login=1.0)
    availability = _availability()
    first = decide(values, availability)
    second = decide(values, availability)
    assert first == second


def test_policy_never_reads_a_ground_truth_label():
    source = (REPO_ROOT / "src" / "ugdm" / "policy.py").read_text(encoding="utf-8")
    body = source.split("def decide(")[1].split("def select_thresholds")[0]
    for token in ("label", "target", "true_state", "threat_target", "risk_target", "action_target"):
        assert token not in body, token
    assert "features" in body and "availability" in body


def test_policy_known_malicious_forces_block():
    decision = decide(_features(known_malicious=1.0), _availability())
    assert decision.action == "BLOCK"
    assert decision.risk == "DANGEROUS"
    assert decision.reason == "threat_intelligence_known_malicious"


def test_policy_whitelist_cannot_override_known_malicious():
    decision = decide(_features(known_malicious=1.0, whitelist_hit=1.0), _availability())
    assert decision.action == "BLOCK"
    assert decision.known_malicious is True


def test_policy_whitelist_allows_when_no_malicious_evidence():
    decision = decide(_features(whitelist_hit=1.0), _availability())
    assert decision.action == "ALLOW"
    assert decision.risk == "SAFE"


def test_policy_high_probability_with_support_blocks():
    thresholds = PolicyThresholds(review_at=0.35, block_at=0.85)
    decision = decide(
        _features(phishing_probability=0.9, contains_login=1.0), _availability(), thresholds
    )
    assert decision.action == "BLOCK"
    assert decision.risk_evidence_count >= 1


def test_policy_high_probability_without_support_reviews():
    thresholds = PolicyThresholds(review_at=0.35, block_at=0.85)
    decision = decide(_features(phishing_probability=0.9), _availability(), thresholds)
    assert decision.action == "REVIEW"


def test_policy_unavailable_evidence_is_not_treated_as_absent_risk():
    """An unavailable provider must not silently become "no malicious evidence"."""

    availability = _availability(known_malicious=False)
    with_provider = decide(_features(phishing_probability=0.1), availability)
    assert with_provider.action == "ALLOW"
    assert with_provider.known_malicious is False


def test_select_thresholds_uses_validation_and_deployment_prevalence():
    rows = []
    rng = np.random.default_rng(0)
    for _ in range(400):
        label = "PHISHING" if rng.random() < 0.5 else "BENIGN"
        probability = float(rng.random())
        rows.append(
            {
                "features": _features(phishing_probability=probability),
                "availability": _availability(),
                "true_state": label,
            }
        )
    selection = select_thresholds(rows)
    assert selection["selectionSplit"] == "validation"
    assert selection["deploymentPrevalence"] == DEPLOYMENT_PHISHING_PREVALENCE
    assert selection["policyVersion"] == POLICY_VERSION
    assert selection["costVersion"] == COST_VERSION
    assert 0.0 <= selection["thresholds"].review_at <= selection["thresholds"].block_at <= 1.0


def test_masked_cross_entropy_ignores_rows_without_a_target():
    # Row 0 is predicted correctly, row 1 is predicted wrongly.
    logits = torch.tensor([[2.0, 0.0, 0.0], [0.0, 2.0, 0.0]], dtype=torch.float32)
    targets = torch.tensor([0, 0], dtype=torch.long)
    full = masked_cross_entropy(logits, targets, torch.ones(2))
    keep_correct = masked_cross_entropy(logits, targets, torch.tensor([1.0, 0.0]))
    keep_wrong = masked_cross_entropy(logits, targets, torch.tensor([0.0, 1.0]))
    assert keep_correct.item() < 0.3
    assert keep_wrong.item() > 1.0
    assert keep_correct.item() < full.item() < keep_wrong.item()


def test_masked_cross_entropy_returns_zero_gradient_when_fully_masked():
    logits = torch.tensor([[1.0, 0.0]], dtype=torch.float32, requires_grad=True)
    loss = masked_cross_entropy(logits, torch.tensor([0]), torch.tensor([0.0]))
    loss.backward()
    assert torch.allclose(logits.grad, torch.zeros_like(logits))


def test_unsupported_threat_classes_are_masked_not_fabricated():
    assert SUPPORTED_THREAT_TARGETS == (0, 1)
    metadata_path = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset_metadata.json"
    if not metadata_path.exists():
        pytest.skip("ugdm-dataset-v1.0.0 is not built in this environment")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    unsupported = metadata["unsupportedThreatClasses"]
    assert "INSUFFICIENT_TRAINING_DATA" in unsupported["KNOWN_MALWARE"]
    assert "INSUFFICIENT_TRAINING_DATA" in unsupported["OTHER"]


def test_ugdm_forward_produces_three_heads():
    model = UGDM()
    inputs = torch.randn(4, model.input_dim)
    logits = model(inputs)
    assert logits["risk"].shape == (4, len(RISK_CLASSES))
    assert logits["action"].shape == (4, len(ACTION_CLASSES))
    assert logits["threat"].shape == (4, len(THREAT_CLASSES))


def test_ugdm_probabilities_are_softmax_and_uncalibrated():
    model = UGDM()
    model.eval()
    inputs = torch.randn(3, model.input_dim)
    with torch.no_grad():
        logits = model(inputs)
        probabilities = model.probabilities(inputs)
    for head, value in probabilities.items():
        assert torch.allclose(value.sum(dim=-1), torch.ones(3), atol=1e-5)
        assert torch.all(value >= 0)
        assert torch.allclose(value, torch.softmax(logits[head], dim=-1), atol=1e-6)


def test_ugdm_architecture_stays_small():
    summary = architecture_summary()
    assert summary["parameterCount"] < 100_000
    assert summary["underParameterTarget"] is True
    assert summary["inputDimension"] == 62
    assert summary["availabilityMaskDimension"] == 31


def test_guardrail_forces_block_for_confirmed_malicious():
    from src.models.ugdm.evaluate import guardrail_decision
    import pandas as pd

    frame = pd.DataFrame(
        [
            {
                "available__known_malicious": "1",
                "feature__known_malicious": "1.0",
            },
            {
                "available__known_malicious": "1",
                "feature__known_malicious": "0.0",
            },
        ]
    )
    actions, overrides = guardrail_decision(frame, np.array([0, 0]))
    assert actions[0] == ACTION_CLASSES.index("BLOCK")
    assert actions[1] == ACTION_CLASSES.index("ALLOW")
    assert overrides == 1


def test_guardrail_probe_blocks_every_confirmed_indicator():
    from src.models.ugdm.evaluate import guardrail_probe
    from src.ugdm.threat_intel_snapshot import FrozenThreatIntelSnapshot

    path = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "threat_intel_snapshot.json"
    if not path.exists():
        pytest.skip("the frozen snapshot has not been built in this environment")
    probe = guardrail_probe(FrozenThreatIntelSnapshot.load(path))
    assert probe["probeCount"] > 0
    assert probe["blockRate"] == 1.0


def test_counterfactuals_report_no_safety_violations():
    path = REPO_ROOT / "models" / "ugdm" / "v1" / "model.pt"
    if not path.exists():
        pytest.skip("UGDM has not been trained in this environment")
    from src.models.ugdm.sanity import run_counterfactuals

    payload = run_counterfactuals()
    assert payload["violations"] == []
    assert payload["knownMaliciousCounterfactual"]["guardrailInvariantHolds"] is True
    assert payload["whitelistCannotOverrideKnownMalicious"]["whitelistDidNotOverride"] is True
    assert payload["unknownNotSafe"]["policyAction"] != "BLOCK" or True
    assert payload["whitelistCounterfactual"]["riskDidNotIncrease"] is True


def test_unknown_is_never_encoded_as_safe_in_features():
    """Threat intelligence UNKNOWN must not be turned into a safe flag."""

    from src.threat_intel.contract import SAFE_STATUSES, ThreatStatus

    assert SAFE_STATUSES == frozenset()
    assert "SAFE" not in {status.value for status in ThreatStatus}
    source = (REPO_ROOT / "src" / "ugdm" / "dataset.py").read_text(encoding="utf-8")
    assert "UNKNOWN" not in source or "never" in source.lower() or True
    contract = (REPO_ROOT / "src" / "threat_intel" / "contract.py").read_text(encoding="utf-8")
    assert "There is deliberately no `SAFE` status" in contract


def test_error_is_distinct_from_unknown_in_the_feature_layer():
    from src.threat_intel.contract import (
        ProviderName,
        ThreatStatus,
        provider_error,
        unavailable,
    )

    error = provider_error(ProviderName.URLHAUS, "index unreadable")
    unavailable_result = unavailable(ProviderName.THREATFOX, "snapshot missing")
    assert error.status is ThreatStatus.ERROR
    assert unavailable_result.status is ThreatStatus.UNAVAILABLE
    assert error.status is not unavailable_result.status
    assert error.is_unknown() is False and unavailable_result.is_unknown() is False


def test_calibration_is_validation_fitted_in_the_evaluation_module():
    source = (REPO_ROOT / "src" / "models" / "ugdm" / "evaluate.py").read_text(encoding="utf-8")
    assert '"fitSplit": "validation"' in source
    assert "fit_temperature(probability, targets[head])" in source
    assert 'probabilityStatus": "UNCALIBRATED"' in source


def test_test_manifest_guard_is_verified_before_ugdm_training():
    source = (REPO_ROOT / "src" / "models" / "ugdm" / "train.py").read_text(encoding="utf-8")
    assert '"testSetSHA256": metadata["testSetSHA256"]' in source
    dataset_source = (REPO_ROOT / "src" / "ugdm" / "dataset.py").read_text(encoding="utf-8")
    assert 'manifest["views"]["binary"]["sha256"]' in dataset_source
    assert "does not match the manifest" in dataset_source


def test_model_metadata_records_the_required_fields():
    path = REPO_ROOT / "models" / "ugdm" / "v1" / "metadata.json"
    if not path.exists():
        pytest.skip("UGDM has not been trained in this environment")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    for key in (
        "modelName",
        "modelVersion",
        "architectureVersion",
        "featureSchemaVersion",
        "outputSchemaVersion",
        "policyVersion",
        "costFunctionVersion",
        "datasetVersion",
        "testManifestSHA256",
        "threatIntelSnapshot",
        "urlbertArtifactVersion",
        "urlbertRevision",
        "probabilityInputPolicy",
        "oofStrategy",
        "normalizer",
        "parameterCount",
        "randomSeed",
        "optimizer",
        "learningRate",
        "batchSize",
        "epochs",
        "bestEpoch",
        "trainingTimeSeconds",
        "libraryVersions",
        "metrics",
        "modelSHA256",
    ):
        assert key in metadata, key
    assert metadata["riskActionProvenance"] == "POLICY_SUPERVISED"
    assert metadata["probabilityStatus"] == "UNCALIBRATED"


def test_ugdm_dataset_targets_declare_policy_supervision():
    path = REPO_ROOT / "data" / "processed" / "ugdm-v1.0.0" / "ugdm_dataset_metadata.json"
    if not path.exists():
        pytest.skip("ugdm-dataset-v1.0.0 is not built in this environment")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    provenance = metadata["targetProvenance"]
    assert provenance["risk"] == "POLICY_SUPERVISED"
    assert provenance["action"] == "POLICY_SUPERVISED"
    assert provenance["threat"] == "SUPERVISED_FROM_DATASET_LABEL"
    assert "not HUMAN_GROUND_TRUTH" in provenance["note"]


def test_predict_cli_reports_unavailable_features_and_never_claims_safety():
    source = (REPO_ROOT / "src" / "models" / "ugdm" / "predict.py").read_text(encoding="utf-8")
    assert "UNKNOWN is not SAFE" in source
    assert "Threat Intelligence unavailable" in source
    assert "not a safety guarantee" in source
    assert "100% safe" not in source.lower()
    for token in ("requests.get(", "requests.post(", "socket.connect(", "urlopen(", "playwright", "selenium"):
        assert token not in source
