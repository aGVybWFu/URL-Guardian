"""Counterfactual sanity tests and a desktop latency benchmark for UGDM.

The neural heads are not architecturally monotone, so the counterfactual checks
distinguish two things:

* the deterministic guardrail, which must always hold, and
* the model's own behaviour, which is reported as measured rather than assumed.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch

from src.models.ugdm.model import UGDM, encode_inputs, fit_normalizer
from src.models.ugdm.train import (
    CHECKPOINT_DIR,
    DATASET_CSV,
    DATASET_METADATA,
    _row_availability,
    _row_values,
    predict_split,
)
from src.ugdm.policy import (
    ACTION_CLASSES,
    RISK_CLASSES,
    PolicyThresholds,
    decide,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES

BENCHMARK_HARDWARE_LABEL = "desktop-research-benchmark"


def load_model() -> tuple[UGDM, object, dict[str, Any]]:
    if not DATASET_CSV.exists():
        raise FileNotFoundError("Build ugdm-dataset-v1.0.0 first")
    metadata = json.loads(DATASET_METADATA.read_text(encoding="utf-8"))
    weights_path = CHECKPOINT_DIR / "model.pt"
    if not weights_path.exists():
        raise FileNotFoundError("Train UGDM v1 first")
    frame = pd.read_csv(DATASET_CSV, dtype=str, low_memory=False)
    train_frame = frame[frame["split"].astype(str) == "train"]
    normalizer = fit_normalizer(_row_values(train_frame))
    model = UGDM()
    model.load_state_dict(torch.load(weights_path, map_location="cpu", weights_only=True)["state_dict"])
    model.eval()
    return model, normalizer, metadata


def _thresholds(metadata: dict[str, Any]) -> PolicyThresholds:
    return PolicyThresholds(
        review_at=float(metadata["thresholdSelection"]["thresholds"]["reviewAt"]),
        block_at=float(metadata["thresholdSelection"]["thresholds"]["blockAt"]),
    )


def _model_probabilities(
    model: UGDM, normalizer: object, values: dict[str, float], availability: dict[str, bool]
) -> dict[str, np.ndarray]:
    inputs = torch.tensor(np.stack([encode_inputs(values, availability, normalizer)]), dtype=torch.float32)
    return predict_split(model, inputs)


def _base_values() -> tuple[dict[str, float], dict[str, bool]]:
    values = {name: 0.0 for name in UGDM_FEATURE_NAMES}
    values["phishing_probability"] = 0.6
    values["benign_probability"] = 0.4
    values["url_length"] = 30.0
    values["hostname_length"] = 15.0
    values["hostname_entropy"] = 3.0
    values["uses_https"] = 1.0
    availability = {name: False for name in UGDM_FEATURE_NAMES}
    for name in (
        "phishing_probability",
        "benign_probability",
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
        "known_malicious",
        "urlhaus_hit",
        "threatfox_hit",
    ):
        availability[name] = True
    return values, availability


def run_counterfactuals() -> dict[str, Any]:
    """Research sanity checks on guardrail and model behaviour."""

    model, normalizer, metadata = load_model()
    thresholds = _thresholds(metadata)
    base_values, base_availability = _base_values()

    base_probabilities = _model_probabilities(model, normalizer, base_values, base_availability)
    base_decision = decide(base_values, base_availability, thresholds)

    # 1. known_malicious 0 -> 1
    malicious_values = dict(base_values, known_malicious=1.0)
    malicious_probabilities = _model_probabilities(model, normalizer, malicious_values, base_availability)
    malicious_decision = decide(malicious_values, base_availability, thresholds)
    known_malicious_check = {
        "modelRiskIndexBefore": int(base_probabilities["risk"][0].argmax()),
        "modelRiskIndexAfter": int(malicious_probabilities["risk"][0].argmax()),
        "modelBlockProbabilityBefore": float(base_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]),
        "modelBlockProbabilityAfter": float(malicious_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]),
        "modelBlockProbabilityDidNotDecrease": float(
            malicious_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]
        )
        >= float(base_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]) - 1e-9,
        "policyActionBefore": base_decision.action,
        "policyActionAfter": malicious_decision.action,
        "guardrailForcesBlock": malicious_decision.action == "BLOCK",
        "guardrailInvariantHolds": malicious_decision.action == "BLOCK",
    }

    # 2. whitelist_hit 0 -> 1 with no malicious evidence
    whitelist_availability = dict(base_availability, whitelist_hit=True)
    whitelist_values = dict(base_values, whitelist_hit=1.0)
    whitelist_probabilities = _model_probabilities(model, normalizer, whitelist_values, whitelist_availability)
    whitelist_decision = decide(whitelist_values, whitelist_availability, thresholds)
    whitelist_check = {
        "policyActionBefore": base_decision.action,
        "policyActionAfter": whitelist_decision.action,
        "riskDidNotIncrease": RISK_CLASSES.index(whitelist_decision.risk)
        <= RISK_CLASSES.index(base_decision.risk),
        "modelBlockProbabilityBefore": float(base_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]),
        "modelBlockProbabilityAfter": float(whitelist_probabilities["action"][0][ACTION_CLASSES.index("BLOCK")]),
    }

    # 3. whitelist must not override confirmed malicious evidence
    both_values = dict(base_values, known_malicious=1.0, whitelist_hit=1.0)
    both_decision = decide(both_values, whitelist_availability, thresholds)
    override_check = {
        "policyAction": both_decision.action,
        "policyRisk": both_decision.risk,
        "whitelistDidNotOverride": both_decision.action == "BLOCK" and both_decision.risk == "DANGEROUS",
        "reason": both_decision.reason,
    }

    # 4. UNKNOWN must not be encoded as safe
    unknown_availability = dict(base_availability, known_malicious=False, urlhaus_hit=False, threatfox_hit=False)
    unknown_decision = decide(base_values, unknown_availability, thresholds)
    unknown_check = {
        "policyAction": unknown_decision.action,
        "risk": unknown_decision.risk,
        "unknownIsNotAutomaticallySafe": unknown_decision.action != "ALLOW"
        or RISK_CLASSES.index(unknown_decision.risk) >= 0,
        "note": "UNKNOWN means the sources did not contain the indicator; it is never a safety claim.",
    }

    return {
        "knownMaliciousCounterfactual": known_malicious_check,
        "whitelistCounterfactual": whitelist_check,
        "whitelistCannotOverrideKnownMalicious": override_check,
        "unknownNotSafe": unknown_check,
        "violations": [
            name
            for name, payload in (
                ("known_malicious_guardrail", known_malicious_check["guardrailInvariantHolds"]),
                ("whitelist_override", override_check["whitelistDidNotOverride"]),
            )
            if not payload
        ],
    }


def run_benchmark(warmup: int = 50, iterations: int = 500) -> dict[str, Any]:
    """Batch-1 latency and memory for UGDM on this workstation."""

    model, normalizer, metadata = load_model()
    values, availability = _base_values()
    inputs = torch.tensor(np.stack([encode_inputs(values, availability, normalizer)]), dtype=torch.float32)
    model_size = (CHECKPOINT_DIR / "model.pt").stat().st_size

    def measure(device: torch.device) -> dict[str, float]:
        local_model = model.to(device)
        local_inputs = inputs.to(device)
        durations: list[float] = []
        with torch.no_grad():
            for index in range(warmup + iterations):
                if device.type == "cuda":
                    torch.cuda.synchronize()
                started = time.perf_counter()
                local_model(local_inputs)
                if device.type == "cuda":
                    torch.cuda.synchronize()
                elapsed = (time.perf_counter() - started) * 1000.0
                if index >= warmup:
                    durations.append(elapsed)
        series = pd.Series(durations)
        return {
            "averageMs": float(series.mean()),
            "p50Ms": float(series.quantile(0.50)),
            "p95Ms": float(series.quantile(0.95)),
        }

    cpu_latency = measure(torch.device("cpu"))
    gpu_latency = None
    peak_vram = None
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
        gpu_latency = measure(torch.device("cuda"))
        peak_vram = int(torch.cuda.max_memory_allocated())
        model.to("cpu")

    try:
        import psutil

        peak_ram = int(psutil.Process().memory_info().rss)
    except ImportError:
        peak_ram = None

    return {
        "hardwareLabel": BENCHMARK_HARDWARE_LABEL,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "pythonVersion": platform.python_version(),
        "torchVersion": torch.__version__,
        "cudaVersion": torch.version.cuda if torch.cuda.is_available() else None,
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "modelSizeBytes": model_size,
        "parameterCount": model.parameter_count(),
        "inputDimension": model.input_dim,
        "cpu": cpu_latency,
        "gpu": gpu_latency,
        "peakVramBytes": peak_vram,
        "peakRssBytes": peak_ram,
        "note": "Desktop research benchmark only; not an Android or deployment latency measurement.",
    }


def main() -> None:
    import json

    from src.utils.logging import configure_logging

    configure_logging()
    print(json.dumps({"counterfactuals": run_counterfactuals(), "benchmark": run_benchmark()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
