"""UGDM training with masked multi-task loss.

Loss contract:

* Threat head: supervised on rows whose label is BENIGN or PHISHING. The
  KNOWN_MALWARE and OTHER classes have no training rows in ugdm-dataset-v1.0.0,
  so their loss contribution is masked rather than filled with fabricated labels.
* Risk and Action heads: supervised by DecisionPolicyV1 targets, which are
  `POLICY_SUPERVISED`, not human ground truth.
* `target_mask` marks which rows contribute to which head.

Model selection uses the Validation decision cost, not overall accuracy.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src.data.snapshot import sha256_file
from src.ugdm.dataset import MANIFEST_PATH, THREAT_INTEL_SNAPSHOT, UGDM_DATASET_VERSION
from src.ugdm.features import feature_spec_payload
from src.ugdm.policy import (
    ACTION_CLASSES,
    DEFAULT_COST,
    RISK_CLASSES,
    THREAT_CLASSES,
    TARGET_PROVENANCE,
    DecisionCost,
    PolicyThresholds,
)
from src.ugdm.schema import UGDM_FEATURE_NAMES
from src.models.ugdm.model import (
    ARCHITECTURE_VERSION,
    FEATURE_SCHEMA_VERSION,
    OUTPUT_SCHEMA_VERSION,
    UGDM,
    architecture_summary,
    encode_inputs,
    fit_normalizer,
)
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
UGDM_MODEL_VERSION = "0.7.0"
DATASET_CSV = Path("data/processed/ugdm-v1.0.0/ugdm_dataset.csv")
DATASET_METADATA = Path("data/processed/ugdm-v1.0.0/ugdm_dataset_metadata.json")
CHECKPOINT_DIR = Path("models/ugdm/v1")

LAMBDA_RISK = 1.0
LAMBDA_ACTION = 1.0
LAMBDA_THREAT = 1.0
SUPPORTED_THREAT_TARGETS = (0, 1)  # BENIGN, PHISHING


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _split_frame(frame: pd.DataFrame, split: str) -> pd.DataFrame:
    return frame[frame["split"].astype(str) == split].reset_index(drop=True)


def _row_values(frame: pd.DataFrame) -> list[dict[str, float]]:
    return [
        {name: float(row[f"feature__{name}"]) for name in UGDM_FEATURE_NAMES}
        for _, row in frame.iterrows()
    ]


def _row_availability(frame: pd.DataFrame) -> list[dict[str, bool]]:
    return [
        {name: bool(row[f"available__{name}"]) for name in UGDM_FEATURE_NAMES}
        for _, row in frame.iterrows()
    ]


def build_tensors(
    frame: pd.DataFrame,
    normalizer: object,
) -> tuple[torch.Tensor, dict[str, torch.Tensor], dict[str, torch.Tensor]]:
    """Build inputs, targets and per-head target masks for one split."""

    values = _row_values(frame)
    availability = _row_availability(frame)
    inputs = torch.tensor(
        np.stack([encode_inputs(v, a, normalizer) for v, a in zip(values, availability)]),
        dtype=torch.float32,
    )
    risk_targets = torch.tensor(frame["risk_target"].astype(int).tolist(), dtype=torch.long)
    action_targets = torch.tensor(frame["action_target"].astype(int).tolist(), dtype=torch.long)
    threat_targets = torch.tensor(frame["threat_target"].astype(int).tolist(), dtype=torch.long)

    supported = torch.tensor(
        [1 if int(value) in SUPPORTED_THREAT_TARGETS else 0 for value in frame["threat_target"]],
        dtype=torch.float32,
    )
    ones = torch.ones(len(frame), dtype=torch.float32)
    targets = {"risk": risk_targets, "action": action_targets, "threat": threat_targets}
    masks = {"risk": ones.clone(), "action": ones.clone(), "threat": supported}
    return inputs, targets, masks


def masked_cross_entropy(
    logits: torch.Tensor,
    targets: torch.Tensor,
    mask: torch.Tensor,
    class_weights: torch.Tensor | None = None,
) -> torch.Tensor:
    """Cross entropy that ignores rows without a reliable target for this head."""

    if mask.sum() <= 0:
        return logits.sum() * 0.0
    per_row = nn.functional.cross_entropy(
        logits, targets, reduction="none", weight=class_weights
    )
    return (per_row * mask).sum() / mask.sum().clamp(min=1.0)


def _class_weights(targets: torch.Tensor, num_classes: int) -> torch.Tensor:
    counts = torch.bincount(targets.clamp(min=0), minlength=num_classes).float()
    counts = torch.where(counts <= 0, torch.ones_like(counts), counts)
    weights = counts.sum() / (num_classes * counts)
    return weights


@torch.no_grad()
def predict_split(
    model: UGDM,
    inputs: torch.Tensor,
    batch_size: int = 1024,
) -> dict[str, np.ndarray]:
    model.eval()
    outputs: dict[str, list[np.ndarray]] = {"risk": [], "action": [], "threat": []}
    for start in range(0, len(inputs), batch_size):
        logits = model(inputs[start : start + batch_size])
        for head, value in logits.items():
            outputs[head].append(torch.softmax(value, dim=-1).numpy())
    return {head: np.concatenate(chunks, axis=0) for head, chunks in outputs.items()}


def _macro_f1(y_true: np.ndarray, y_pred: np.ndarray, num_classes: int) -> float:
    from sklearn.metrics import f1_score

    labels = list(range(num_classes))
    return float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))


def _head_metrics(y_true: np.ndarray, probabilities: np.ndarray, num_classes: int) -> dict[str, Any]:
    predicted = probabilities.argmax(axis=1)
    from sklearn.metrics import classification_report, confusion_matrix

    names = {3: RISK_CLASSES, 4: THREAT_CLASSES}.get(num_classes)
    if names is None:
        names = ACTION_CLASSES
    report = classification_report(
        y_true, predicted, labels=list(range(num_classes)), target_names=list(names),
        output_dict=True, zero_division=0,
    )
    return {
        "macroF1": _macro_f1(y_true, predicted, num_classes),
        "accuracy": float((predicted == y_true).mean()) if len(y_true) else 0.0,
        "perClass": {name: report[name] for name in names},
        "confusionMatrix": confusion_matrix(y_true, predicted, labels=list(range(num_classes))).tolist(),
        "classNames": list(names),
    }


def operational_metrics(
    frame: pd.DataFrame,
    action_probabilities: np.ndarray,
    cost: DecisionCost = DEFAULT_COST,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Security outcomes that matter more than accuracy."""

    labels = frame["label"].astype(str).to_numpy()
    actions = np.array(ACTION_CLASSES)[action_probabilities.argmax(axis=1)]
    benign = labels == "BENIGN"
    phishing = labels == "PHISHING"

    def rate(mask: np.ndarray, action: str) -> float:
        return float((actions[mask] == action).mean()) if mask.any() else 0.0

    pairs = [
        (("PHISHING" if label == "PHISHING" else "BENIGN"), action)
        for label, action in zip(labels, actions)
    ]
    # Expected cost is reported at the deployment prevalence used by the policy.
    from src.ugdm.policy import DEPLOYMENT_PHISHING_PREVALENCE, prevalence_weights

    weights = prevalence_weights([state for state, _ in pairs], DEPLOYMENT_PHISHING_PREVALENCE)
    total = sum(weight * cost.cost_of(state, action) for weight, (state, action) in zip(weights, pairs))
    weight_sum = sum(weights)
    return {
        "phishingBlockRecall": rate(phishing, "BLOCK"),
        "phishingReviewRate": rate(phishing, "REVIEW"),
        "phishingAllowRate": rate(phishing, "ALLOW"),
        "benignBlockRate": rate(benign, "BLOCK"),
        "benignReviewRate": rate(benign, "REVIEW"),
        "benignAllowRate": rate(benign, "ALLOW"),
        "overallReviewRate": float((actions == "REVIEW").mean()),
        "overallBlockRate": float((actions == "BLOCK").mean()),
        "expectedDecisionCost": float(total / weight_sum) if weight_sum else 0.0,
        "costVersion": cost.version,
        "deploymentPrevalence": DEPLOYMENT_PHISHING_PREVALENCE,
        "thresholdsApplied": threshold,
    }


def train(
    epochs: int = 50,
    patience: int = 8,
    batch_size: int = 512,
    learning_rate: float = 1e-3,
    weight_decay: float = 1e-4,
    seed: int = 42,
    variant: str = "full",
) -> dict[str, Any]:
    """Train UGDM v1 and select the best epoch on Validation decision cost."""

    configure_logging()
    set_seed(seed)
    if not DATASET_CSV.exists():
        raise FileNotFoundError("Build ugdm-dataset-v1.0.0 before training")
    frame = pd.read_csv(DATASET_CSV, dtype=str, low_memory=False)
    metadata = json.loads(DATASET_METADATA.read_text(encoding="utf-8"))
    thresholds = PolicyThresholds(
        review_at=float(metadata["thresholdSelection"]["thresholds"]["reviewAt"]),
        block_at=float(metadata["thresholdSelection"]["thresholds"]["blockAt"]),
    )

    train_frame = _split_frame(frame, "train")
    validation_frame = _split_frame(frame, "validation")
    test_frame = _split_frame(frame, "test")

    excluded = {
        "no_threat_intel": ("known_malicious", "urlhaus_hit", "threatfox_hit"),
        "no_urlbert": ("phishing_probability", "benign_probability"),
        "lexical_only": (
            "phishing_probability",
            "benign_probability",
            "known_malicious",
            "urlhaus_hit",
            "threatfox_hit",
        ),
    }.get(variant, ())

    normalizer = fit_normalizer(_row_values(train_frame))
    train_inputs, train_targets, train_masks = build_tensors(train_frame, normalizer)
    validation_inputs, validation_targets, validation_masks = build_tensors(validation_frame, normalizer)
    test_inputs, test_targets, test_masks = build_tensors(test_frame, normalizer)

    if excluded:
        for name in excluded:
            index = UGDM_FEATURE_NAMES.index(name)
            train_inputs[:, index] = 0.0
            train_inputs[:, len(UGDM_FEATURE_NAMES) + index] = 0.0
            validation_inputs[:, index] = 0.0
            validation_inputs[:, len(UGDM_FEATURE_NAMES) + index] = 0.0
            test_inputs[:, index] = 0.0
            test_inputs[:, len(UGDM_FEATURE_NAMES) + index] = 0.0

    model = UGDM()
    risk_weights = _class_weights(train_targets["risk"], 3)
    action_weights = _class_weights(train_targets["action"], 3)
    threat_weights = _class_weights(train_targets["threat"], 4)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    dataset = TensorDataset(
        train_inputs, train_targets["risk"], train_targets["action"], train_targets["threat"],
        train_masks["risk"], train_masks["action"], train_masks["threat"],
    )
    generator = torch.Generator()
    generator.manual_seed(seed)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, generator=generator)

    cost = DEFAULT_COST
    best: dict[str, Any] | None = None
    history: list[dict[str, Any]] = []
    started = time.perf_counter()
    epochs_without_improvement = 0

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss = 0.0
        for batch in loader:
            inputs = batch[0]
            risk_t, action_t, threat_t = batch[1], batch[2], batch[3]
            risk_m, action_m, threat_m = batch[4], batch[5], batch[6]
            logits = model(inputs)
            loss = (
                LAMBDA_RISK * masked_cross_entropy(logits["risk"], risk_t, risk_m, risk_weights)
                + LAMBDA_ACTION * masked_cross_entropy(logits["action"], action_t, action_m, action_weights)
                + LAMBDA_THREAT * masked_cross_entropy(logits["threat"], threat_t, threat_m, threat_weights)
            )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optimizer.step()
            epoch_loss += float(loss.item()) * len(inputs)
        scheduler.step()

        validation_probabilities = predict_split(model, validation_inputs)
        validation_metrics = operational_metrics(validation_frame, validation_probabilities["action"], cost)
        entry = {
            "epoch": epoch,
            "trainLoss": epoch_loss / max(1, len(train_frame)),
            "validationExpectedCost": validation_metrics["expectedDecisionCost"],
            "validationRiskMacroF1": _head_metrics(
                validation_targets["risk"].numpy(), validation_probabilities["risk"], 3
            )["macroF1"],
            "validationActionMacroF1": _head_metrics(
                validation_targets["action"].numpy(), validation_probabilities["action"], 3
            )["macroF1"],
            "validationThreatMacroF1": _head_metrics(
                validation_targets["threat"].numpy(), validation_probabilities["threat"], 4
            )["macroF1"],
        }
        history.append(entry)
        if epoch % 5 == 0 or epoch == 1:
            LOGGER.info(
                "epoch %d loss %.4f valCost %.4f riskF1 %.4f actionF1 %.4f threatF1 %.4f",
                epoch,
                entry["trainLoss"],
                entry["validationExpectedCost"],
                entry["validationRiskMacroF1"],
                entry["validationActionMacroF1"],
                entry["validationThreatMacroF1"],
            )
        if best is None or entry["validationExpectedCost"] < best["entry"]["validationExpectedCost"] - 1e-9:
            best = {
                "entry": entry,
                "state": {key: value.clone() for key, value in model.state_dict().items()},
            }
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= patience:
                LOGGER.info("Early stopping at epoch %d", epoch)
                break

    if best is None:
        raise RuntimeError("Training produced no checkpoint")
    model.load_state_dict(best["state"])
    training_seconds = time.perf_counter() - started

    directory = Path(CHECKPOINT_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    suffix = "" if variant == "full" else f"_{variant}"
    weights_path = directory / f"model{suffix}.pt"
    torch.save({"state_dict": model.state_dict(), "variant": variant}, weights_path)

    validation_probabilities = predict_split(model, validation_inputs)
    test_probabilities = predict_split(model, test_inputs)
    metrics = {
        "variant": variant,
        "excludedFeatures": list(excluded),
        "bestEpoch": best["entry"]["epoch"],
        "epochsCompleted": len(history),
        "validation": {
            "operational": operational_metrics(validation_frame, validation_probabilities["action"], cost),
            "risk": _head_metrics(validation_targets["risk"].numpy(), validation_probabilities["risk"], 3),
            "action": _head_metrics(validation_targets["action"].numpy(), validation_probabilities["action"], 3),
            "threat": _head_metrics(validation_targets["threat"].numpy(), validation_probabilities["threat"], 4),
        },
        "test": {
            "operational": operational_metrics(test_frame, test_probabilities["action"], cost),
            "risk": _head_metrics(test_targets["risk"].numpy(), test_probabilities["risk"], 3),
            "action": _head_metrics(test_targets["action"].numpy(), test_probabilities["action"], 3),
            "threat": _head_metrics(test_targets["threat"].numpy(), test_probabilities["threat"], 4),
        },
        "history": history,
    }
    metadata_payload = {
        "metadataSchemaVersion": 1,
        "modelName": "ugdm",
        "modelVersion": UGDM_MODEL_VERSION,
        "variant": variant,
        "architectureVersion": ARCHITECTURE_VERSION,
        "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "datasetVersion": metadata["sourceDatasetVersion"],
        "ugdmDatasetVersion": UGDM_DATASET_VERSION,
        "testManifestSHA256": sha256_file(MANIFEST_PATH),
        "testSetSHA256": metadata["testSetSHA256"],
        "threatIntelSnapshot": metadata["threatIntelSnapshot"],
        "urlbertArtifactVersion": "URLBERT_PHISHING_BINARY_V1",
        "urlbertRevision": "020744435b3be870dabb2bba0b41237bea69b84b",
        "probabilityInputPolicy": metadata["probabilityInputPolicy"],
        "oofStrategy": metadata["splitAssignmentSource"],
        "policyVersion": metadata["thresholdSelection"]["policyVersion"],
        "costFunctionVersion": metadata["thresholdSelection"]["costVersion"],
        "policyThresholds": metadata["thresholdSelection"]["thresholds"],
        "normalizer": normalizer.to_dict(),
        "featureSchema": feature_spec_payload(),
        "architecture": architecture_summary(),
        "parameterCount": model.parameter_count(),
        "randomSeed": seed,
        "optimizer": "AdamW",
        "learningRate": learning_rate,
        "weightDecay": weight_decay,
        "batchSize": batch_size,
        "epochs": epochs,
        "bestEpoch": best["entry"]["epoch"],
        "trainingTimeSeconds": round(training_seconds, 3),
        "targetProvenance": metadata["targetProvenance"],
        "riskActionProvenance": TARGET_PROVENANCE,
        "threatTargetClassesSupported": ["BENIGN", "PHISHING"],
        "unsupportedThreatClasses": metadata["unsupportedThreatClasses"],
        "probabilityStatus": "UNCALIBRATED",
        "libraryVersions": {
            "python": platform.python_version(),
            "torch": torch.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
        "metrics": metrics,
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "modelSHA256": sha256_file(weights_path),
    }
    (directory / f"metadata{suffix}.json").write_text(
        json.dumps(metadata_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LOGGER.info(
        "%s: best epoch %d validation cost %.4f",
        variant,
        best["entry"]["epoch"],
        best["entry"]["validationExpectedCost"],
    )
    return metadata_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Train UGDM v1 on ugdm-dataset-v1.0.0")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument(
        "--variant",
        default="full",
        choices=["full", "no_threat_intel", "no_urlbert", "lexical_only"],
    )
    args = parser.parse_args()
    try:
        payload = train(
            epochs=args.epochs,
            patience=args.patience,
            learning_rate=args.learning_rate,
            variant=args.variant,
        )
        print(
            json.dumps(
                {
                    "variant": payload["variant"],
                    "bestEpoch": payload["bestEpoch"],
                    "parameterCount": payload["parameterCount"],
                    "testOperational": payload["metrics"]["test"]["operational"],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
