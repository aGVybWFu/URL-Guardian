"""UGDM prediction CLI.

Reports risk, action and threat probabilities plus the evidence that produced
them. It never claims a URL is safe: `UNKNOWN` threat intelligence is shown as
"not found in the intelligence sources", and an unavailable provider is shown as
unavailable rather than as "no threats found".
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch

from src.data.normalizer import normalize_url
from src.data.snapshot import sha256_file
from src.models.ugdm.model import UGDM, encode_inputs, fit_normalizer
from src.models.ugdm.train import CHECKPOINT_DIR, DATASET_CSV, DATASET_METADATA, _row_values
from src.ugdm.features import (
    AVAILABILITY_NOT_IMPLEMENTED,
    FEATURE_SPEC_BY_NAME,
    UGDMFeatureAvailabilityMask,
    default_availability,
)
from src.ugdm.policy import ACTION_CLASSES, RISK_CLASSES, THREAT_CLASSES, PolicyThresholds, decide
from src.ugdm.schema import UGDM_FEATURE_NAMES
from src.ugdm.threat_intel_snapshot import FrozenThreatIntelSnapshot
from src.utils.logging import get_logger

LOGGER = get_logger(__name__)
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


def _load_runtime() -> tuple[UGDM, object, dict[str, Any], dict[str, Any], FrozenThreatIntelSnapshot]:
    if not DATASET_CSV.exists():
        raise FileNotFoundError("Build ugdm-dataset-v1.0.0 first")
    dataset_metadata = json.loads(DATASET_METADATA.read_text(encoding="utf-8"))
    model_metadata_path = CHECKPOINT_DIR / "metadata.json"
    if not model_metadata_path.exists():
        raise FileNotFoundError("Train UGDM v1 first")
    model_metadata = json.loads(model_metadata_path.read_text(encoding="utf-8"))
    weights_path = CHECKPOINT_DIR / "model.pt"
    frame = pd.read_csv(DATASET_CSV, dtype=str, low_memory=False)
    train_frame = frame[frame["split"].astype(str) == "train"]
    normalizer = fit_normalizer(_row_values(train_frame))
    model = UGDM()
    model.load_state_dict(torch.load(weights_path, map_location="cpu", weights_only=True)["state_dict"])
    model.eval()
    snapshot = FrozenThreatIntelSnapshot.load(Path(dataset_metadata["threatIntelSnapshot"]["file"]))
    return model, normalizer, dataset_metadata, model_metadata, snapshot


def _urlbert_probability(domain: str, metadata: dict[str, Any]) -> tuple[float, float, str]:
    """Look up the URLBERT probability for an in-dataset domain when available."""

    if not DATASET_CSV.exists():
        return 0.5, 0.5, "unavailable"
    frame = pd.read_csv(DATASET_CSV, dtype=str, low_memory=False)
    match = frame[frame["registrable_domain"].astype(str) == domain]
    if match.empty:
        return 0.5, 0.5, "unavailable_not_in_dataset"
    row = match.iloc[0]
    return (
        float(row["feature__phishing_probability"]),
        float(row["feature__benign_probability"]),
        f"from {row['split']} split features",
    )


def predict_url(url: str) -> dict[str, Any]:
    """Produce a UGDM decision for one URL string, analysed statically."""

    from src.features.extractor import extract_features

    model, normalizer, metadata, model_metadata, snapshot = _load_runtime()
    parsed = normalize_url(url)
    domain = parsed.registrable_domain
    if not domain:
        raise ValueError("Input did not reduce to a registrable domain")

    phishing_probability, benign_probability, probability_source = _urlbert_probability(domain, metadata)

    features = extract_features(parsed)
    values: dict[str, float] = {name: 0.0 for name in UGDM_FEATURE_NAMES}
    values["phishing_probability"] = phishing_probability
    values["benign_probability"] = benign_probability
    for extractor_name, ugdm_name in EXTRACTOR_TO_UGDM.items():
        if extractor_name in features:
            values[ugdm_name] = float(features[extractor_name])

    provider_status = snapshot.payload.get("providerStatus") or {}
    availability = default_availability(provider_status)
    threat_intel_status = "AVAILABLE" if any(s == "AVAILABLE" for s in provider_status.values()) else "UNAVAILABLE"
    if threat_intel_status == "AVAILABLE":
        urlhaus_hit = snapshot.contains(parsed.hostname) or snapshot.contains(domain)
        values["urlhaus_hit"] = 1.0 if urlhaus_hit else 0.0
        values["known_malicious"] = 1.0 if urlhaus_hit else 0.0

    inputs = torch.tensor([encode_inputs(values, availability, normalizer)], dtype=torch.float32)
    with torch.no_grad():
        probabilities = model.probabilities(inputs)

    thresholds = PolicyThresholds(
        review_at=float(metadata["thresholdSelection"]["thresholds"]["reviewAt"]),
        block_at=float(metadata["thresholdSelection"]["thresholds"]["blockAt"]),
    )
    policy = decide(values, availability, thresholds)

    model_action = ACTION_CLASSES[int(probabilities["action"].argmax())]
    guardrail_applied = policy.known_malicious
    final_action = "BLOCK" if guardrail_applied else model_action

    if threat_intel_status != "AVAILABLE":
        threat_intel_note = "Threat Intelligence unavailable: no provider could be queried."
    elif policy.known_malicious:
        threat_intel_note = "Confirmed malicious indicator found in the frozen intelligence snapshot."
    else:
        threat_intel_note = "Indicator not found in the intelligence sources. UNKNOWN is not SAFE."

    unsupported = {
        name for name, spec in FEATURE_SPEC_BY_NAME.items()
        if spec.availability == AVAILABILITY_NOT_IMPLEMENTED
    }
    return {
        "resultType": "UGDM Model Prediction",
        "input": url,
        "normalizedUrl": parsed.normalized_url,
        "registrableDomain": domain,
        "modelVersion": model_metadata["modelVersion"],
        "architectureVersion": model_metadata["architectureVersion"],
        "risk": {
            name: float(probabilities["risk"][0][index]) for index, name in enumerate(RISK_CLASSES)
        },
        "action": {
            name: float(probabilities["action"][0][index]) for index, name in enumerate(ACTION_CLASSES)
        },
        "threat": {
            name: float(probabilities["threat"][0][index]) for index, name in enumerate(THREAT_CLASSES)
        },
        "finalAction": final_action,
        "guardrailApplied": guardrail_applied,
        "policyVersion": metadata["thresholdSelection"]["policyVersion"],
        "policyReferenceAction": policy.action,
        "evidence": {
            "urlbertPhishingProbability": phishing_probability,
            "urlbertProbabilitySource": probability_source,
            "threatIntelligenceStatus": threat_intel_status,
            "threatIntelligenceNote": threat_intel_note,
            "knownMalicious": policy.known_malicious,
            "riskEvidenceCount": policy.risk_evidence_count,
            "policyReason": policy.reason,
        },
        "unavailableFeatures": sorted(unsupported),
        "probabilityStatus": "UNCALIBRATED",
        "disclaimer": (
            "Model prediction, not a safety guarantee. Absence of intelligence evidence is not "
            "evidence of safety."
        ),
        "testSetSHA256": model_metadata["testSetSHA256"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a UGDM decision for one URL string")
    parser.add_argument("url")
    args = parser.parse_args()
    try:
        print(json.dumps(predict_url(args.url), ensure_ascii=False, indent=2))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
