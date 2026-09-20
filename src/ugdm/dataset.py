"""UGDM dataset construction (ugdm-dataset-v1.0.0).

The dataset references `dataset-v1.3.0` and reuses its frozen split assignment
unchanged. It never re-splits, never deletes rows and never rewrites labels.

Per row it stores: row id, split, registrable domain, feature vector, availability
mask, targets and provenance. No secret is ever written.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.data.snapshot import sha256_file
from src.features.extractor import extract_feature_frame
from src.ugdm.features import (
    AVAILABILITY_MASK_DIMENSION,
    AVAILABILITY_NOT_IMPLEMENTED,
    FEATURE_SPEC_BY_NAME,
    UGDMFeatureAvailabilityMask,
    feature_spec_payload,
)
from src.ugdm.policy import (
    ACTION_TO_INDEX,
    RISK_TO_INDEX,
    TARGET_PROVENANCE,
    THREAT_TO_INDEX,
    PolicyThresholds,
    decide,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES
from src.ugdm.threat_intel_snapshot import FrozenThreatIntelSnapshot

UGDM_DATASET_VERSION = "ugdm-dataset-v1.0.0"
SOURCE_DATASET_VERSION = "dataset-v1.3.0"
SPLITS_ROOT = Path("data/splits/v1.3.0/binary")
MANIFEST_PATH = Path("data/splits/v1.3.0/test_manifest_v1.3.0.json")
OOF_DIR = Path("data/processed/ugdm-v1.0.0/oof")
THREAT_INTEL_SNAPSHOT = Path("data/processed/ugdm-v1.0.0/threat_intel_snapshot.json")

EXTRACTOR_TO_UGDM = {
    "url_length": "url_length",
    "hostname_length": "hostname_length",
    "subdomain_count": "subdomain_count",
    "digit_ratio": "digit_ratio",
    "special_character_ratio": "special_character_ratio",
    "hostname_entropy": "hostname_entropy",
    "has_ip_address": "has_ip",
    "has_punycode": "has_punycode",
    "has_at_symbol": "has_at_symbol",
    "is_https": "uses_https",
    "has_non_default_port": "has_non_default_port",
    "contains_login": "contains_login",
    "contains_verify": "contains_verify",
    "contains_secure": "contains_secure",
    "contains_account": "contains_account",
    "contains_password": "contains_password",
    "contains_payment": "contains_payment",
    "contains_wallet": "contains_wallet",
}


@dataclass(frozen=True)
class ProbabilityInputPolicy:
    """Which URLBERT probability version UGDM consumes, chosen on Validation."""

    version: str
    chosen_on: str
    validation_ece: float
    validation_brier: float
    validation_nll: float
    alternative_version: str
    alternative_validation_ece: float
    alternative_validation_brier: float
    alternative_validation_nll: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "chosenVersion": self.version,
            "chosenOn": self.chosen_on,
            "validationMetrics": {
                "ece": self.validation_ece,
                "brier": self.validation_brier,
                "nll": self.validation_nll,
            },
            "alternativeVersion": self.alternative_version,
            "alternativeValidationMetrics": {
                "ece": self.alternative_validation_ece,
                "brier": self.alternative_validation_brier,
                "nll": self.alternative_validation_nll,
            },
            "selectionRule": (
                "Chosen on Validation only by lowest expected calibration error, then lowest Brier "
                "score, then lowest NLL. The Test Set never participates."
            ),
        }


def _binary_metrics(probabilities: np.ndarray, labels: np.ndarray) -> dict[str, float]:
    from src.evaluation.calibration import expected_calibration_error, multiclass_brier, negative_log_likelihood

    return {
        "ece": expected_calibration_error(probabilities, labels),
        "brier": multiclass_brier(probabilities, labels),
        "nll": negative_log_likelihood(probabilities, labels),
    }


def select_probability_input_policy(validation_probabilities: np.ndarray, labels: np.ndarray) -> ProbabilityInputPolicy:
    """Compare uncalibrated versus temperature-scaled URLBERT on Validation only."""

    from src.evaluation.calibration import apply_temperature, fit_temperature

    fitted = fit_temperature(validation_probabilities, labels)
    calibrated = apply_temperature(validation_probabilities, fitted["temperature"])
    uncalibrated_metrics = _binary_metrics(validation_probabilities, labels)
    calibrated_metrics = _binary_metrics(calibrated, labels)

    def ranking(metrics: dict[str, float]) -> tuple[float, float, float]:
        return (metrics["ece"], metrics["brier"], metrics["nll"])

    if ranking(calibrated_metrics) < ranking(uncalibrated_metrics):
        chosen, alternative = "calibrated", "uncalibrated"
        chosen_metrics, alternative_metrics = calibrated_metrics, uncalibrated_metrics
    else:
        chosen, alternative = "uncalibrated", "calibrated"
        chosen_metrics, alternative_metrics = uncalibrated_metrics, calibrated_metrics
    return ProbabilityInputPolicy(
        version=chosen,
        chosen_on="validation",
        validation_ece=chosen_metrics["ece"],
        validation_brier=chosen_metrics["brier"],
        validation_nll=chosen_metrics["nll"],
        alternative_version=alternative,
        alternative_validation_ece=alternative_metrics["ece"],
        alternative_validation_brier=alternative_metrics["brier"],
        alternative_validation_nll=alternative_metrics["nll"],
    )


def _load_probability_table(path: Path, split: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Missing URLBERT probability table: {path}")
    frame = pd.read_csv(path, dtype=str, low_memory=False)
    frame["phishing_probability"] = frame["phishing_probability"].astype(float)
    frame["benign_probability"] = frame["benign_probability"].astype(float)
    frame["split"] = split
    return frame


def build_feature_rows(
    split: str,
    frame: pd.DataFrame,
    probabilities: pd.DataFrame,
    snapshot: FrozenThreatIntelSnapshot,
    thresholds: PolicyThresholds,
    calibrated: bool = False,
    temperature: float = 1.0,
) -> pd.DataFrame:
    """Assemble the UGDM feature matrix, availability mask and targets for one split."""

    extractor = extract_feature_frame(frame["model_url"])
    rows: list[dict[str, Any]] = []
    availability_defaults = {
        name: spec.availability != AVAILABILITY_NOT_IMPLEMENTED
        for name, spec in FEATURE_SPEC_BY_NAME.items()
    }
    threat_intel_available = all(
        status == "AVAILABLE" for status in (snapshot.payload.get("providerStatus") or {}).values()
    ) and bool(snapshot.payload.get("providerStatus"))

    phishing = probabilities["phishing_probability"].to_numpy()
    benign = probabilities["benign_probability"].to_numpy()
    if calibrated:
        from src.evaluation.calibration import apply_temperature

        stacked = np.column_stack([benign, phishing])
        scaled = apply_temperature(stacked, temperature)
        benign, phishing = scaled[:, 0], scaled[:, 1]

    for position in range(len(frame)):
        values: dict[str, float] = {name: 0.0 for name in UGDM_FEATURE_NAMES}
        availability: dict[str, bool] = dict(availability_defaults)
        for name in ("known_malicious", "urlhaus_hit", "threatfox_hit"):
            availability[name] = threat_intel_available
        values["phishing_probability"] = float(phishing[position])
        values["benign_probability"] = float(benign[position])
        for extractor_name, ugdm_name in EXTRACTOR_TO_UGDM.items():
            if extractor_name in extractor.columns:
                values[ugdm_name] = float(extractor.iloc[position][extractor_name])
        hostname = str(frame.iloc[position]["hostname"])
        registrable_domain = str(frame.iloc[position]["registrable_domain"])
        if threat_intel_available:
            urlhaus_hit = snapshot.contains(hostname) or snapshot.contains(registrable_domain)
            values["urlhaus_hit"] = 1.0 if urlhaus_hit else 0.0
            values["threatfox_hit"] = 0.0
            values["known_malicious"] = 1.0 if urlhaus_hit else 0.0
        mask = UGDMFeatureAvailabilityMask.from_availability(availability)
        decision = decide(values, availability, thresholds)
        label = str(frame.iloc[position]["label"])
        rows.append(
            {
                "rowId": f"{split}:{position}",
                "split": split,
                "registrable_domain": registrable_domain,
                "source": str(frame.iloc[position]["source"]),
                "label": label,
                **{f"feature__{name}": values[name] for name in UGDM_FEATURE_NAMES},
                **{f"available__{name}": int(flag) for name, flag in zip(UGDM_FEATURE_NAMES, mask.flags)},
                "threat_target": THREAT_TO_INDEX[label],
                "risk_target": RISK_TO_INDEX[decision.risk],
                "action_target": ACTION_TO_INDEX[decision.action],
                "policy_reason": decision.reason,
                "risk_evidence_count": decision.risk_evidence_count,
                "known_malicious_evidence": int(decision.known_malicious),
            }
        )
    return pd.DataFrame(rows)


def build_ugdm_dataset(
    output_dir: str | Path = "data/processed/ugdm-v1.0.0",
    thresholds: PolicyThresholds | None = None,
) -> dict[str, Any]:
    """Build ugdm-dataset-v1.0.0 from dataset-v1.3.0 and the frozen intelligence snapshot."""

    from src.ugdm.policy import DEFAULT_THRESHOLDS, select_thresholds

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest["datasetVersion"] != SOURCE_DATASET_VERSION:
        raise RuntimeError("The binary Test Manifest does not belong to dataset-v1.3.0")
    test_path = SPLITS_ROOT / "test.csv"
    if sha256_file(test_path) != manifest["views"]["binary"]["sha256"]:
        raise RuntimeError("Sealed binary Test Set does not match the manifest")

    snapshot = FrozenThreatIntelSnapshot.load(THREAT_INTEL_SNAPSHOT)
    oof_train = _load_probability_table(OOF_DIR / "oof_train_probabilities.csv", "train")
    validation_probabilities = _load_probability_table(OOF_DIR / "validation_probabilities.csv", "validation")
    test_probabilities = _load_probability_table(OOF_DIR / "test_probabilities.csv", "test")

    train_frame = pd.read_csv(SPLITS_ROOT / "train.csv", dtype=str, low_memory=False)
    validation_frame = pd.read_csv(SPLITS_ROOT / "validation.csv", dtype=str, low_memory=False)
    test_frame = pd.read_csv(test_path, dtype=str, low_memory=False)

    validation_labels = validation_frame["label"].map({"BENIGN": 0, "PHISHING": 1}).to_numpy(dtype=int)
    validation_stack = np.column_stack(
        [
            validation_probabilities["benign_probability"].to_numpy(),
            validation_probabilities["phishing_probability"].to_numpy(),
        ]
    )
    probability_policy = select_probability_input_policy(validation_stack, validation_labels)
    from src.evaluation.calibration import apply_temperature, fit_temperature

    fitted_temperature = float(fit_temperature(validation_stack, validation_labels)["temperature"])
    use_calibrated = probability_policy.version == "calibrated"

    if thresholds is None:
        validation_rows = []
        preliminary = build_feature_rows(
            "validation",
            validation_frame,
            validation_probabilities,
            snapshot,
            DEFAULT_THRESHOLDS,
            calibrated=use_calibrated,
            temperature=fitted_temperature,
        )
        for _, row in preliminary.iterrows():
            validation_rows.append(
                {
                    "features": {name: float(row[f"feature__{name}"]) for name in UGDM_FEATURE_NAMES},
                    "availability": {name: bool(row[f"available__{name}"]) for name in UGDM_FEATURE_NAMES},
                    "true_state": str(row["label"]),
                }
            )
        selection = select_thresholds(validation_rows)
        thresholds = selection["thresholds"]
    else:
        selection = {"thresholds": thresholds, "selectionSplit": "provided"}

    train_rows = build_feature_rows(
        "train", train_frame, oof_train, snapshot, thresholds,
        calibrated=use_calibrated, temperature=fitted_temperature,
    )
    validation_rows_frame = build_feature_rows(
        "validation", validation_frame, validation_probabilities, snapshot, thresholds,
        calibrated=use_calibrated, temperature=fitted_temperature,
    )
    test_rows = build_feature_rows(
        "test", test_frame, test_probabilities, snapshot, thresholds,
        calibrated=use_calibrated, temperature=fitted_temperature,
    )

    combined = pd.concat([train_rows, validation_rows_frame, test_rows], ignore_index=True)
    combined.to_csv(directory / "ugdm_dataset.csv", index=False, lineterminator="\n")

    target_summary = {}
    for split, frame in (("train", train_rows), ("validation", validation_rows_frame), ("test", test_rows)):
        target_summary[split] = {
            "rows": int(len(frame)),
            "threatTargetDistribution": {
                str(key): int(value) for key, value in frame["threat_target"].value_counts().sort_index().items()
            },
            "riskTargetDistribution": {
                str(key): int(value) for key, value in frame["risk_target"].value_counts().sort_index().items()
            },
            "actionTargetDistribution": {
                str(key): int(value) for key, value in frame["action_target"].value_counts().sort_index().items()
            },
            "knownMaliciousRows": int(frame["known_malicious_evidence"].sum()),
        }

    metadata: dict[str, Any] = {
        "metadataSchemaVersion": 1,
        "ugdmDatasetVersion": UGDM_DATASET_VERSION,
        "sourceDatasetVersion": SOURCE_DATASET_VERSION,
        "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rowCount": int(len(combined)),
        "splits": target_summary,
        "featureSchema": feature_spec_payload(),
        "availabilityMaskDimension": AVAILABILITY_MASK_DIMENSION,
        "probabilityInputPolicy": probability_policy.to_dict(),
        "probabilityInputTemperature": fitted_temperature,
        "thresholdSelection": {
            "thresholds": thresholds.to_dict(),
            "selectionSplit": selection.get("selectionSplit"),
            "validationExpectedCost": selection.get("validationExpectedCost"),
            "costVersion": selection.get("costVersion"),
            "policyVersion": selection.get("policyVersion"),
        },
        "targetProvenance": {
            "threat": "SUPERVISED_FROM_DATASET_LABEL",
            "risk": TARGET_PROVENANCE,
            "action": TARGET_PROVENANCE,
            "note": (
                "Risk and Action targets are produced by DecisionPolicyV1 from runtime-available "
                "evidence. They are POLICY_SUPERVISED, not HUMAN_GROUND_TRUTH."
            ),
        },
        "threatIntelSnapshot": {
            "file": THREAT_INTEL_SNAPSHOT.as_posix(),
            "sha256": sha256_file(THREAT_INTEL_SNAPSHOT),
            "indicatorCount": snapshot.indicator_count,
            "providerStatus": snapshot.payload.get("providerStatus"),
        },
        "unsupportedThreatClasses": {
            "KNOWN_MALWARE": "INSUFFICIENT_TRAINING_DATA: no row in dataset-v1.3.0 carries confirmed malware evidence",
            "OTHER": "INSUFFICIENT_TRAINING_DATA: no reliable supervised source exists",
        },
        "splitAssignmentSource": "dataset-v1.3.0 frozen splits, reused unchanged; no re-split was performed",
        "testManifestSHA256": sha256_file(MANIFEST_PATH),
        "testSetSHA256": manifest["views"]["binary"]["sha256"],
    }
    (directory / "ugdm_dataset_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return metadata
