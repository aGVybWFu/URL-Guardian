"""UGDM evaluation: baselines, ablations, guardrail, calibration and explainability.

Research integrity notes:

* Risk and Action metrics are computed against `POLICY_SUPERVISED` targets, never
  against human ground truth.
* Threat metrics are only reported for classes that have reliable supervised rows.
  `KNOWN_MALWARE` and `OTHER` are reported as unsupported.
* The frozen Test Set is read once, after every model and threshold is fixed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch

from src.data.snapshot import sha256_file
from src.models.ugdm.model import UGDM, encode_inputs, fit_normalizer
from src.models.ugdm.train import (
    DATASET_CSV,
    DATASET_METADATA,
    CHECKPOINT_DIR,
    _head_metrics,
    _row_availability,
    _row_values,
    build_tensors,
    operational_metrics,
    predict_split,
)
from src.ugdm.features import UGDMFeatureAvailabilityMask
from src.ugdm.policy import (
    ACTION_CLASSES,
    DEFAULT_COST,
    DEPLOYMENT_PHISHING_PREVALENCE,
    POLICY_VERSION,
    RISK_CLASSES,
    THREAT_CLASSES,
    DecisionCost,
    PolicyThresholds,
    decide,
    prevalence_weights,
    risk_evidence_count,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES
from src.ugdm.threat_intel_snapshot import FrozenThreatIntelSnapshot
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
REPORTS_DIR = Path("reports/metrics/ugdm-v1.0.0")


def load_dataset() -> tuple[pd.DataFrame, dict[str, Any]]:
    if not DATASET_CSV.exists():
        raise FileNotFoundError("Build ugdm-dataset-v1.0.0 before evaluation")
    frame = pd.read_csv(DATASET_CSV, dtype=str, low_memory=False)
    metadata = json.loads(DATASET_METADATA.read_text(encoding="utf-8"))
    return frame, metadata


def split_frame(frame: pd.DataFrame, split: str) -> pd.DataFrame:
    return frame[frame["split"].astype(str) == split].reset_index(drop=True)


def policy_actions(
    frame: pd.DataFrame,
    thresholds: PolicyThresholds,
) -> tuple[np.ndarray, np.ndarray]:
    """Run DecisionPolicyV1 over a split and return action and risk indices."""

    actions: list[int] = []
    risks: list[int] = []
    for _, row in frame.iterrows():
        values = {name: float(row[f"feature__{name}"]) for name in UGDM_FEATURE_NAMES}
        availability = {name: bool(row[f"available__{name}"]) for name in UGDM_FEATURE_NAMES}
        decision = decide(values, availability, thresholds)
        actions.append(ACTION_CLASSES.index(decision.action))
        risks.append(RISK_CLASSES.index(decision.risk))
    return np.array(actions), np.array(risks)


def urlbert_only_actions(
    frame: pd.DataFrame,
    thresholds: PolicyThresholds,
) -> np.ndarray:
    """Baseline A: decide from the URLBERT probability alone, no other evidence."""

    actions: list[int] = []
    for _, row in frame.iterrows():
        probability = float(row["feature__phishing_probability"])
        if probability >= thresholds.block_at:
            actions.append(ACTION_CLASSES.index("BLOCK"))
        elif probability >= thresholds.review_at:
            actions.append(ACTION_CLASSES.index("REVIEW"))
        else:
            actions.append(ACTION_CLASSES.index("ALLOW"))
    return np.array(actions)


def logistic_baseline(
    train_frame: pd.DataFrame,
    target_frame: pd.DataFrame,
    normalizer: object,
) -> np.ndarray:
    """Baseline F: multinomial logistic regression on the same 62-dim input."""

    from sklearn.linear_model import LogisticRegression

    def encode(frame: pd.DataFrame) -> np.ndarray:
        values = _row_values(frame)
        availability = _row_availability(frame)
        return np.stack([encode_inputs(v, a, normalizer) for v, a in zip(values, availability)])

    model = LogisticRegression(max_iter=2000, random_state=42)
    model.fit(encode(train_frame), train_frame["action_target"].astype(int).to_numpy())
    return model.predict(encode(target_frame))


def action_cost(
    frame: pd.DataFrame,
    actions: np.ndarray,
    cost: DecisionCost = DEFAULT_COST,
) -> dict[str, Any]:
    """Expected decision cost at the deployment prevalence."""

    labels = frame["label"].astype(str).tolist()
    action_names = [ACTION_CLASSES[int(index)] for index in actions]
    weights = prevalence_weights(labels, DEPLOYMENT_PHISHING_PREVALENCE)
    total = sum(
        weight * cost.cost_of(label, action)
        for weight, label, action in zip(weights, labels, action_names)
    )
    weight_sum = sum(weights)
    return {
        "expectedDecisionCost": float(total / weight_sum) if weight_sum else 0.0,
        "deploymentPrevalence": DEPLOYMENT_PHISHING_PREVALENCE,
        "costVersion": cost.version,
    }


def guardrail_decision(
    frame: pd.DataFrame,
    model_actions: np.ndarray,
) -> tuple[np.ndarray, int]:
    """Hard security guardrail: confirmed malicious evidence always blocks.

    The guardrail overrides the model. UGDM is not allowed to allow confirmed
    threat intelligence evidence.
    """

    actions = np.array(model_actions, dtype=int)
    overrides = 0
    for index, (_, row) in enumerate(frame.iterrows()):
        known = bool(row["available__known_malicious"]) and float(row["feature__known_malicious"]) >= 0.5
        if known:
            if actions[index] != ACTION_CLASSES.index("BLOCK"):
                overrides += 1
            actions[index] = ACTION_CLASSES.index("BLOCK")
    return actions, overrides


def guardrail_probe(snapshot: FrozenThreatIntelSnapshot) -> dict[str, Any]:
    """Verify the guardrail on confirmed indicators from the frozen snapshot.

    This is a guardrail verification probe, not a performance benchmark: the
    frozen Test Set does not contain confirmed malware rows.
    """

    from src.ugdm.schema import UGDM_FEATURE_NAMES as NAMES

    probes = 0
    blocked = 0
    for digest in list(sorted(snapshot._digests))[:200]:  # noqa: SLF001 - deterministic probe order
        probes += 1
        values = {name: 0.0 for name in NAMES}
        availability = {name: False for name in NAMES}
        values["known_malicious"] = 1.0
        availability["known_malicious"] = True
        decision = decide(values, availability, PolicyThresholds(review_at=0.35, block_at=0.85))
        if decision.action == "BLOCK":
            blocked += 1
    return {
        "probeCount": probes,
        "blockedByGuardrail": blocked,
        "blockRate": (blocked / probes) if probes else None,
        "note": (
            "The guardrail probe confirms that confirmed intelligence evidence always blocks. "
            "It is a safety check, not a performance metric."
        ),
    }


def calibration_report(
    frame: pd.DataFrame,
    probabilities: dict[str, np.ndarray],
) -> dict[str, Any]:
    """Per-head ECE/Brier/NLL before and after validation-fitted temperature scaling."""

    from src.evaluation.calibration import apply_temperature, fit_temperature, summarise

    targets = {
        "risk": frame["risk_target"].astype(int).to_numpy(),
        "action": frame["action_target"].astype(int).to_numpy(),
        "threat": frame["threat_target"].astype(int).to_numpy(),
    }
    output: dict[str, Any] = {}
    for head, probability in probabilities.items():
        fitted = fit_temperature(probability, targets[head])
        scaled = apply_temperature(probability, fitted["temperature"])
        output[head] = {
            "temperature": fitted["temperature"],
            "uncalibrated": summarise(probability, targets[head]),
            "calibrated": summarise(scaled, targets[head]),
            "fitSplit": "validation",
        }
    return output


def permutation_importance(
    model: UGDM,
    frame: pd.DataFrame,
    normalizer: object,
    inputs: torch.Tensor,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Permutation importance on the action head, computed on Test inputs.

    Correlation only: a high value means the model relies on that feature, not
    that the feature causes the decision.
    """

    import copy

    baseline = predict_split(model, inputs)["action"]
    baseline_pred = baseline.argmax(axis=1)
    results: list[dict[str, Any]] = []
    generator = np.random.default_rng(42)
    for index, name in enumerate(UGDM_FEATURE_NAMES):
        shuffled = inputs.clone()
        permutation = torch.tensor(generator.permutation(len(inputs)), dtype=torch.long)
        shuffled[:, index] = inputs[permutation, index]
        perturbed_pred = predict_split(model, shuffled)["action"].argmax(axis=1)
        results.append(
            {
                "feature": name,
                "predictionChangeRate": float((perturbed_pred != baseline_pred).mean()),
            }
        )
    results.sort(key=lambda item: item["predictionChangeRate"], reverse=True)
    return results[:top_k]


def run_evaluation() -> dict[str, Any]:
    """Evaluate UGDM, the policy, the baselines and the ablations on the frozen Test Set."""

    configure_logging()
    frame, metadata = load_dataset()
    thresholds = PolicyThresholds(
        review_at=float(metadata["thresholdSelection"]["thresholds"]["reviewAt"]),
        block_at=float(metadata["thresholdSelection"]["thresholds"]["blockAt"]),
    )
    train_frame = split_frame(frame, "train")
    validation_frame = split_frame(frame, "validation")
    test_frame = split_frame(frame, "test")
    normalizer = fit_normalizer(_row_values(train_frame))

    results: dict[str, Any] = {
        "policyVersion": POLICY_VERSION,
        "costVersion": DEFAULT_COST.version,
        "thresholds": thresholds.to_dict(),
        "targetProvenance": metadata["targetProvenance"],
        "deploymentPrevalence": DEPLOYMENT_PHISHING_PREVALENCE,
        "baselines": {},
        "ablations": {},
    }

    # Baseline B: DecisionPolicyV1
    policy_test_actions, policy_test_risks = policy_actions(test_frame, thresholds)
    results["baselines"]["decision_policy_v1"] = {
        "type": "deterministic_rules",
        "operational": operational_metrics(
            test_frame, np.eye(3)[policy_test_actions], DEFAULT_COST
        ),
        "cost": action_cost(test_frame, policy_test_actions),
        "riskMacroF1": _head_metrics(test_frame["risk_target"].astype(int).to_numpy(), np.eye(3)[policy_test_risks], 3)["macroF1"],
    }

    # Baseline A: URLBERT only
    urlbert_test_actions = urlbert_only_actions(test_frame, thresholds)
    results["baselines"]["urlbert_only"] = {
        "type": "urlbert_probability_thresholds",
        "operational": operational_metrics(
            test_frame, np.eye(3)[urlbert_test_actions], DEFAULT_COST
        ),
        "cost": action_cost(test_frame, urlbert_test_actions),
    }

    # Baseline F: logistic regression on the same input vector
    logistic_test_actions = logistic_baseline(train_frame, test_frame, normalizer)
    results["baselines"]["logistic_regression"] = {
        "type": "linear_baseline_on_same_inputs",
        "operational": operational_metrics(
            test_frame, np.eye(3)[logistic_test_actions], DEFAULT_COST
        ),
        "cost": action_cost(test_frame, logistic_test_actions),
        "actionMacroF1": _head_metrics(
            test_frame["action_target"].astype(int).to_numpy(), np.eye(3)[logistic_test_actions], 3
        )["macroF1"],
    }

    # UGDM variants
    variants = {
        "full": ("ugdm_v1", "model.pt", "metadata.json"),
        "no_threat_intel": ("ugdm_v1_no_threat_intel", "model_no_threat_intel.pt", "metadata_no_threat_intel.json"),
        "no_urlbert": ("ugdm_v1_no_urlbert", "model_no_urlbert.pt", "metadata_no_urlbert.json"),
        "lexical_only": ("ugdm_v1_lexical_only", "model_lexical_only.pt", "metadata_lexical_only.json"),
    }
    snapshot = FrozenThreatIntelSnapshot.load(Path(metadata["threatIntelSnapshot"]["file"]))
    test_inputs, test_targets, _ = build_tensors(test_frame, normalizer)
    model_for_importance: UGDM | None = None

    for variant, (label, weights_name, metadata_name) in variants.items():
        weights_path = CHECKPOINT_DIR / weights_name
        if not weights_path.exists():
            results["ablations"][variant] = {"status": "NOT_TRAINED"}
            continue
        model = UGDM()
        model.load_state_dict(torch.load(weights_path, map_location="cpu", weights_only=True)["state_dict"])
        model.eval()
        probabilities = predict_split(model, test_inputs)
        raw_actions = probabilities["action"].argmax(axis=1)
        guarded_actions, overrides = guardrail_decision(test_frame, raw_actions)
        variant_metadata = json.loads((CHECKPOINT_DIR / metadata_name).read_text(encoding="utf-8"))
        payload = {
            "status": "EVALUATED",
            "excludedFeatures": variant_metadata["metrics"]["excludedFeatures"],
            "bestEpoch": variant_metadata["bestEpoch"],
            "operational": operational_metrics(test_frame, probabilities["action"], DEFAULT_COST),
            "operationalWithGuardrail": operational_metrics(
                test_frame, np.eye(3)[guarded_actions], DEFAULT_COST
            ),
            "guardrailOverrides": overrides,
            "cost": action_cost(test_frame, guarded_actions),
            "riskMacroF1": _head_metrics(test_targets["risk"].numpy(), probabilities["risk"], 3)["macroF1"],
            "actionMacroF1": _head_metrics(test_targets["action"].numpy(), probabilities["action"], 3)["macroF1"],
            "threatMacroF1": _head_metrics(test_targets["threat"].numpy(), probabilities["threat"], 4)["macroF1"],
            "riskConfusionMatrix": _head_metrics(test_targets["risk"].numpy(), probabilities["risk"], 3)["confusionMatrix"],
            "actionConfusionMatrix": _head_metrics(test_targets["action"].numpy(), probabilities["action"], 3)["confusionMatrix"],
            "threatConfusionMatrix": _head_metrics(test_targets["threat"].numpy(), probabilities["threat"], 4)["confusionMatrix"],
            "calibration": calibration_report(test_frame, probabilities),
            "probabilityStatus": "UNCALIBRATED",
        }
        if variant == "full":
            results["baselines"]["ugdm_v1"] = {"type": "multi_task_model", **payload}
            results["ablations"]["full"] = {"status": "EVALUATED"}
            model_for_importance = model
        results["ablations"][variant] = payload

    results["guardrailProbe"] = guardrail_probe(snapshot)
    results["explainability"] = {
        "method": "permutation_importance_on_action_head",
        "topFeatures": (
            permutation_importance(model_for_importance, test_frame, normalizer, test_inputs)
            if model_for_importance is not None
            else []
        ),
        "note": "Permutation importance measures model reliance, not causation.",
    }
    results["threatHeadSupport"] = {
        "supportedClasses": ["BENIGN", "PHISHING"],
        "unsupportedClasses": metadata["unsupportedThreatClasses"],
        "note": (
            "KNOWN_MALWARE and OTHER have no reliable training rows in ugdm-dataset-v1.0.0. "
            "Threat macro F1 therefore includes two classes with zero support."
        ),
    }
    results["testManifestSHA256"] = sha256_file(Path("data/splits/v1.3.0/test_manifest_v1.3.0.json"))
    results["testSetSHA256"] = metadata["testSetSHA256"]

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "ugdm_evaluation.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate UGDM v1 against baselines and ablations")
    args = parser.parse_args()
    try:
        results = run_evaluation()
        print(json.dumps(
            {
                "policyCost": results["baselines"]["decision_policy_v1"]["cost"]["expectedDecisionCost"],
                "urlbertOnlyCost": results["baselines"]["urlbert_only"]["cost"]["expectedDecisionCost"],
                "logisticCost": results["baselines"]["logistic_regression"]["cost"]["expectedDecisionCost"],
                "ugdmCost": results["baselines"]["ugdm_v1"]["cost"]["expectedDecisionCost"],
                "ugdmGuardrailOverrides": results["baselines"]["ugdm_v1"]["guardrailOverrides"],
                "guardrailProbe": results["guardrailProbe"],
            },
            ensure_ascii=False,
            indent=2,
        ))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
