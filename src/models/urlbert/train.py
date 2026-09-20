"""Official Phase 2 URLBERT fine-tuning.

Training uses the frozen Train and Validation splits only. The sealed Test CSV
is never opened on this code path; only the Test Manifest hashes are verified
before training starts.
"""

from __future__ import annotations

import json
import platform
import random
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn

from src.evaluation.metrics import calculate_binary_metrics, calculate_metrics
from src.models.urlbert.config import URLBERTConfig, load_urlbert_config
from src.models.urlbert.dataset import (
    DatasetContractError,
    class_weights_from_labels,
    labels_of,
    load_training_frames,
    texts_of,
    tokenize_frame,
    validate_frozen_contract,
    verify_frozen_test_manifest,
)
from src.models.urlbert.model import (
    CheckpointInfo,
    URLBertClassifier,
    load_encoder,
    save_checkpoint,
)
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def set_deterministic_seed(seed: int) -> dict[str, object]:
    """Seed Python, NumPy, PyTorch and CUDA, and request deterministic kernels."""

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if torch.cuda.is_available():
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    return {
        "pythonRandom": True,
        "numpy": True,
        "torch": True,
        "cudaManualSeed": bool(torch.cuda.is_available()),
        "deterministicAlgorithms": "warn_only",
        "cudnnDeterministic": bool(torch.cuda.is_available()),
    }


def gpu_report() -> dict[str, object]:
    """Describe the compute device actually used for this run."""

    if not torch.cuda.is_available():
        raise RuntimeError(
            "CUDA is not available. Phase 2 training refuses to silently run a long CPU job; "
            "install a CUDA-enabled PyTorch build and retry."
        )
    properties = torch.cuda.get_device_properties(0)
    return {
        "device": "cuda",
        "name": torch.cuda.get_device_name(0),
        "vramBytes": int(properties.total_memory),
        "vramGb": round(properties.total_memory / 1024**3, 2),
        "cudaVersion": torch.version.cuda,
        "torchVersion": torch.__version__,
        "computeCapability": f"{properties.major}.{properties.minor}",
    }


def resolve_amp_dtype(setting: str) -> torch.dtype | None:
    """Pick the mixed-precision dtype that is actually usable on this GPU."""

    if setting == "off" or not torch.cuda.is_available():
        return None
    if setting == "bf16":
        return torch.bfloat16
    if setting == "fp16":
        return torch.float16
    return torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16


def select_batch_size(
    model: URLBertClassifier,
    input_ids: torch.Tensor,
    attention_mask: torch.Tensor,
    labels: torch.Tensor,
    candidates: list[int],
    device: torch.device,
    amp_dtype: torch.dtype | None,
    class_weights: torch.Tensor,
) -> int:
    """Probe the largest candidate batch size that completes a training step."""

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    available = input_ids.shape[0]
    for candidate in sorted({min(size, available) for size in candidates if size > 0}, reverse=True):
        try:
            model.zero_grad(set_to_none=True)
            batch_ids = input_ids[:candidate].to(device)
            batch_mask = attention_mask[:candidate].to(device)
            batch_labels = labels[:candidate].to(device)
            with torch.autocast(device_type="cuda", dtype=amp_dtype, enabled=amp_dtype is not None):
                logits = model(batch_ids, batch_mask)
                loss = criterion(logits, batch_labels)
            loss.backward()
            model.zero_grad(set_to_none=True)
            torch.cuda.empty_cache()
            return int(candidate)
        except torch.cuda.OutOfMemoryError:
            model.zero_grad(set_to_none=True)
            torch.cuda.empty_cache()
            continue
        except RuntimeError as error:
            if "out of memory" not in str(error).lower():
                raise
            model.zero_grad(set_to_none=True)
            torch.cuda.empty_cache()
            continue
    raise RuntimeError("Unable to fit even the smallest configured batch size in VRAM")


@torch.no_grad()
def evaluate_split(
    model: URLBertClassifier,
    input_ids: torch.Tensor,
    attention_mask: torch.Tensor,
    labels: torch.Tensor,
    batch_size: int,
    device: torch.device,
    amp_dtype: torch.dtype | None,
    num_classes: int = 3,
) -> dict[str, Any]:
    """Compute loss and metrics for one split without updating the model."""

    model.eval()
    criterion = nn.CrossEntropyLoss()
    loss_sum = 0.0
    probabilities: list[np.ndarray] = []
    for start in range(0, input_ids.shape[0], batch_size):
        stop = start + batch_size
        batch_ids = input_ids[start:stop].to(device)
        batch_mask = attention_mask[start:stop].to(device)
        batch_labels = labels[start:stop].to(device)
        with torch.autocast(device_type="cuda", dtype=amp_dtype, enabled=amp_dtype is not None):
            logits = model(batch_ids, batch_mask)
            loss = criterion(logits, batch_labels)
        loss_sum += float(loss.item()) * batch_ids.shape[0]
        probabilities.append(torch.softmax(logits.float(), dim=-1).cpu().numpy())
    stacked = np.concatenate(probabilities, axis=0)
    y_true = labels.numpy()
    y_pred = stacked.argmax(axis=1)
    calculator = calculate_binary_metrics if int(num_classes) == 2 else calculate_metrics
    metrics = calculator(y_true, y_pred, stacked)
    metrics["loss"] = loss_sum / max(1, int(labels.shape[0]))
    return metrics


def _epoch_entry(
    epoch: int,
    train_loss: float,
    validation_metrics: dict[str, Any],
    label_names: list[str],
) -> dict[str, Any]:
    """Normalise per-epoch metrics for both the binary and three-class heads.

    The early-stopping score is macro F1 for three classes and phishing F1 for the
    binary head, which is the same quantity in each case: the mean F1 over the
    classes actually present in the label space.
    """

    per_class_recall = {
        name: validation_metrics["per_class"][name]["recall"] for name in label_names
    }
    if len(label_names) == 2:
        entry = {
            "epoch": epoch,
            "trainLoss": train_loss,
            "validationLoss": validation_metrics["loss"],
            "validationAccuracy": validation_metrics["accuracy"],
            "validationPrecision": validation_metrics["precision"],
            "validationRecall": validation_metrics["recall"],
            "validationF1": validation_metrics["f1"],
            "validationSpecificity": validation_metrics["specificity"],
            "validationFalsePositiveRate": validation_metrics["false_positive_rate"],
            "validationFalseNegativeRate": validation_metrics["false_negative_rate"],
            "validationAuroc": validation_metrics.get("auroc"),
            "validationAuprc": validation_metrics.get("auprc"),
            "validationPerClassRecall": per_class_recall,
            "selectionMetric": "phishing_f1",
            "selectionValue": float(validation_metrics["f1"]),
        }
        return entry
    return {
        "epoch": epoch,
        "trainLoss": train_loss,
        "validationLoss": validation_metrics["loss"],
        "validationAccuracy": validation_metrics["accuracy"],
        "validationMacroPrecision": validation_metrics["macro_precision"],
        "validationMacroRecall": validation_metrics["macro_recall"],
        "validationMacroF1": validation_metrics["macro_f1"],
        "validationPerClassRecall": per_class_recall,
        "validationPhishingRecall": validation_metrics["phishing_recall"],
        "validationMalwareRecall": validation_metrics["malware_recall"],
        "validationBenignFpr": validation_metrics["benign_false_positive_rate"],
        "selectionMetric": "macro_f1",
        "selectionValue": float(validation_metrics["macro_f1"]),
    }


def _loader_versions() -> dict[str, str]:
    import sklearn
    import transformers

    return {
        "python": platform.python_version(),
        "torch": torch.__version__,
        "transformers": transformers.__version__,
        "numpy": np.__version__,
        "scikit-learn": sklearn.__version__,
    }


def train(config_path: str | Path | None = None, config: URLBERTConfig | None = None) -> Path:
    """Run the official URLBERT_DOMAIN_ONLY_V1 fine-tuning."""

    configure_logging()
    urlbert = config or load_urlbert_config(config_path)
    started = time.perf_counter()
    if not torch.cuda.is_available():
        gpu_report()  # raises with an explicit environment report
    device = torch.device("cuda")

    # Integrity check only: verify the sealed Test Manifest hash and its recorded
    # Test hashes. The actual Test CSV is never opened on the training path.
    manifest = verify_frozen_test_manifest(urlbert, verify_test_files=False)
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(urlbert.base_model, revision=urlbert.base_model_revision)
    frames = load_training_frames(urlbert)
    contract = validate_frozen_contract(urlbert, frames, require_all_splits=False)

    deterministic = set_deterministic_seed(urlbert.seed)
    gpu = gpu_report()
    amp_dtype = resolve_amp_dtype(str(urlbert.training.get("mixed_precision", "auto")))

    tokenized = {
        split: tokenize_frame(frame, split, urlbert, tokenizer)
        for split, frame in frames.items()
    }
    train_split = tokenized["train"]
    validation_split = tokenized["validation"]

    class_weights = class_weights_from_labels(labels_of(frames["train"], urlbert), urlbert.num_classes)
    LOGGER.info("Train class weights: %s", class_weights)
    weights_tensor = torch.tensor(class_weights, dtype=torch.float32)

    encoder, encoder_spec = load_encoder(urlbert.base_model, urlbert.base_model_revision)
    model = URLBertClassifier(
        encoder,
        num_classes=urlbert.num_classes,
        hidden_size=urlbert.head_hidden_size,
        dropout=urlbert.head_dropout,
        pooling=urlbert.pooling,
    ).to(device)

    configured_batch = int(urlbert.training.get("batch_size", 0))
    if configured_batch > 0:
        batch_size = configured_batch
    else:
        candidates = [int(value) for value in urlbert.training.get("batch_size_candidates", [256, 128, 64])]
        minimum_steps = int(urlbert.training.get("minimum_steps_per_epoch", 1))
        step_cap = max(1, len(train_split) // max(1, minimum_steps))
        capped = [size for size in candidates if size <= step_cap] or [step_cap]
        batch_size = select_batch_size(
            model,
            train_split.input_ids,
            train_split.attention_mask,
            train_split.labels,
            capped,
            device,
            amp_dtype,
            weights_tensor.to(device),
        )
    LOGGER.info(
        "Selected batch size: %d (%d optimizer steps per epoch)",
        batch_size,
        int(np.ceil(len(train_split) / batch_size)),
    )

    epochs = urlbert.epochs
    learning_rate = float(urlbert.training["learning_rate"])
    weight_decay = float(urlbert.training["weight_decay"])
    warmup_ratio = float(urlbert.training.get("warmup_ratio", 0.1))
    max_grad_norm = float(urlbert.training.get("max_grad_norm", 1.0))
    patience = int(urlbert.training.get("early_stopping_patience", 2))
    accumulation = max(1, int(urlbert.training.get("gradient_accumulation_steps", 1)))

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    steps_per_epoch = max(1, int(np.ceil(len(train_split) / batch_size / accumulation)))
    total_steps = steps_per_epoch * epochs
    warmup_steps = max(1, int(total_steps * warmup_ratio))

    def schedule(step: int) -> float:
        if step < warmup_steps:
            return float(step) / float(warmup_steps)
        remaining = max(0, total_steps - step)
        span = max(1, total_steps - warmup_steps)
        return max(0.0, float(remaining) / float(span))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, schedule)
    criterion = nn.CrossEntropyLoss(weight=weights_tensor.to(device))
    use_scaler = amp_dtype == torch.float16
    scaler = torch.amp.GradScaler("cuda", enabled=use_scaler)

    generator = torch.Generator()
    generator.manual_seed(urlbert.seed)
    checkpoint_dir = urlbert.path("checkpoint_dir")
    history: list[dict[str, Any]] = []
    best_macro_f1 = -1.0
    best_epoch = -1
    best_path: Path | None = None
    epochs_without_improvement = 0

    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()

    for epoch in range(1, epochs + 1):
        model.train()
        permutation = torch.randperm(len(train_split), generator=generator)
        epoch_loss = 0.0
        seen = 0
        optimizer.zero_grad(set_to_none=True)
        for step, start in enumerate(range(0, len(train_split), batch_size), start=1):
            selection = permutation[start : start + batch_size]
            batch_ids = train_split.input_ids[selection].to(device)
            batch_mask = train_split.attention_mask[selection].to(device)
            batch_labels = train_split.labels[selection].to(device)
            with torch.autocast(device_type="cuda", dtype=amp_dtype, enabled=amp_dtype is not None):
                logits = model(batch_ids, batch_mask)
                loss = criterion(logits, batch_labels) / accumulation
            if use_scaler:
                scaler.scale(loss).backward()
            else:
                loss.backward()
            if step % accumulation == 0 or start + batch_size >= len(train_split):
                if use_scaler:
                    scaler.unscale_(optimizer)
                    nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
                    optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
            epoch_loss += float(loss.item()) * accumulation * batch_ids.shape[0]
            seen += int(batch_ids.shape[0])

        train_loss = epoch_loss / max(1, seen)
        validation_metrics = evaluate_split(
            model,
            validation_split.input_ids,
            validation_split.attention_mask,
            validation_split.labels,
            batch_size,
            device,
            amp_dtype,
            urlbert.num_classes,
        )
        entry = _epoch_entry(epoch, train_loss, validation_metrics, urlbert.label_names)
        history.append(entry)
        LOGGER.info(
            "epoch %d/%d train_loss=%.4f val_loss=%.4f val_acc=%.4f val_%s=%.4f",
            epoch,
            epochs,
            entry["trainLoss"],
            entry["validationLoss"],
            entry["validationAccuracy"],
            entry["selectionMetric"],
            entry["selectionValue"],
        )

        if entry["selectionValue"] > best_macro_f1:
            best_macro_f1 = float(entry["selectionValue"])
            best_epoch = epoch
            epochs_without_improvement = 0
            checkpoint_path = save_checkpoint(
                checkpoint_dir,
                "best",
                model,
                tokenizer,
                CheckpointInfo(
                    experiment_id=urlbert.experiment_id,
                    epoch=epoch,
                    validation_macro_f1=best_macro_f1,
                ),
            )
            best_path = checkpoint_path
        else:
            epochs_without_improvement += 1
        save_checkpoint(
            checkpoint_dir,
            "last",
            model,
            tokenizer,
            CheckpointInfo(
                experiment_id=urlbert.experiment_id,
                epoch=epoch,
                validation_macro_f1=float(entry["selectionValue"]),
            ),
        )
        if epochs_without_improvement >= patience:
            LOGGER.info("Early stopping at epoch %d", epoch)
            break

    if best_path is None:
        raise RuntimeError("Training finished without a best checkpoint")

    training_seconds = time.perf_counter() - started
    peak_vram = int(torch.cuda.max_memory_allocated()) if torch.cuda.is_available() else 0
    resolved_batch = batch_size
    metadata: dict[str, Any] = {
        "metadataSchemaVersion": 1,
        "experimentType": "OFFICIAL_EXPERIMENT",
        "modelName": urlbert.raw.get("model_name", "url_guardian_urlbert"),
        "modelVersion": urlbert.raw.get("model_version", "unknown"),
        "experimentId": urlbert.experiment_id,
        "baseModel": urlbert.base_model,
        "baseModelRevision": urlbert.base_model_revision,
        "baseModelArchitecture": encoder_spec.architecture,
        "baseModelParams": encoder_spec.params,
        "totalParams": model.total_parameters(),
        "trainableParams": model.trainable_parameters(),
        "datasetVersion": urlbert.dataset_version,
        "datasetView": urlbert.dataset_view,
        "featureRepresentation": f"DOMAIN_ONLY registrable-domain text ({urlbert.text_column})",
        "textColumn": urlbert.text_column,
        "testManifestSHA256": urlbert.raw.get("expected_test_manifest_sha256"),
        "testSetSHA256": manifest.get("views", {}).get(urlbert.dataset_view, {}).get("sha256"),
        "labelMapping": urlbert.label_mapping,
        "randomSeed": urlbert.seed,
        "deterministicSettings": deterministic,
        "determinismNotes": (
            "Seeds are fixed for Python, NumPy, PyTorch and CUDA, cudnn is set to deterministic mode, and "
            "torch.use_deterministic_algorithms uses warn_only. CUDA attention backward kernels and GPU "
            "reduction order are still not guaranteed to be bitwise reproducible across runs or hardware."
        ),
        "classWeights": {
            name: class_weights[index] for index, name in enumerate(urlbert.label_names)
        },
        "numClasses": urlbert.num_classes,
        "classWeightSource": "train split class distribution only",
        "lossFunction": "weighted cross entropy",
        "tokenizer": {
            "name": urlbert.base_model,
            "revision": urlbert.base_model_revision,
            "class": type(tokenizer).__name__,
            "vocabSize": int(tokenizer.vocab_size),
            "specialTokens": {str(key): str(value) for key, value in tokenizer.special_tokens_map.items()},
        },
        "maxLength": urlbert.max_length,
        "pooling": urlbert.pooling,
        "headHiddenSize": urlbert.head_hidden_size,
        "headDropout": urlbert.head_dropout,
        "epochs": urlbert.epochs,
        "epochsCompleted": len(history),
        "batchSize": resolved_batch,
        "batchSizeSelection": (
            "largest VRAM-fitting candidate that keeps at least "
            f"{int(urlbert.training.get('minimum_steps_per_epoch', 1))} optimizer steps per epoch"
        ),
        "optimizerStepsPerEpoch": int(np.ceil(len(train_split) / resolved_batch)),
        "gradientAccumulationSteps": accumulation,
        "learningRate": learning_rate,
        "optimizer": "AdamW",
        "scheduler": f"linear warmup ({warmup_ratio}) + linear decay",
        "weightDecay": weight_decay,
        "maxGradNorm": max_grad_norm,
        "mixedPrecision": str(amp_dtype) if amp_dtype is not None else "off",
        "libraryVersions": _loader_versions(),
        "gpu": gpu,
        "trainingTimeSeconds": round(training_seconds, 3),
        "peakVramBytes": peak_vram,
        "bestValidationEpoch": best_epoch,
        "bestValidationMacroF1": best_macro_f1,
        "bestValidationSelectionMetric": next(
            (entry["selectionMetric"] for entry in history if entry["epoch"] == best_epoch), None
        ),
        "trainCount": int(len(train_split)),
        "validationCount": int(len(validation_split)),
        "testCount": int(manifest.get("views", {}).get(urlbert.dataset_view, {}).get("record_count", 0)),
        "datasetContract": contract,
        "history": history,
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "testMetrics": None,
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "environment": {"platform": platform.platform(), "processor": platform.processor()},
    }
    from src.data.snapshot import sha256_file

    metadata["modelSHA256"] = sha256_file(best_path)
    metadata_path = checkpoint_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    (checkpoint_dir / "history.json").write_text(
        json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LOGGER.info(
        "Saved best URLBERT checkpoint to %s (epoch %d, val macro F1 %.4f)",
        best_path,
        best_epoch,
        best_macro_f1,
    )
    return best_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Fine-tune the URLBERT DOMAIN_ONLY classifier on the frozen Train Set")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        path = train(args.config)
        print(path)
    except (DatasetContractError, FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
