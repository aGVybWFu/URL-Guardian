"""Official Phase 2 URLBERT evaluation on the frozen Test Set.

The Test Set is opened exactly once, after the best checkpoint has already been
chosen from Validation. No tuning decision is made with Test information.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch

from src.data.snapshot import sha256_file
from src.evaluation.metrics import LABEL_NAMES, calculate_binary_metrics, calculate_metrics
from src.evaluation.plots import plot_confusion_matrix
from src.models.urlbert.config import URLBERTConfig, load_urlbert_config
from src.models.urlbert.dataset import (
    DatasetContractError,
    load_frozen_split,
    tokenize_frame,
    validate_frozen_contract,
    verify_frozen_test_manifest,
)
from src.models.urlbert.model import load_checkpoint
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)

COMPARISON_COLUMNS = [
    "Model",
    "Dataset View",
    "Accuracy",
    "Macro Precision",
    "Macro Recall",
    "Macro F1",
    "Weighted F1",
    "Phishing Recall",
    "Malware Recall",
    "Benign FPR",
    "Malicious FNR",
    "AUROC",
    "AUPRC",
    "Experiment Type",
    "Dataset Version",
    "Model Version",
    "Model SHA-256",
    "Test Manifest SHA-256",
    "Test Set SHA-256",
]


@torch.no_grad()
def predict_frame(
    model: torch.nn.Module,
    frame: pd.DataFrame,
    config: URLBERTConfig,
    tokenizer: object,
    device: torch.device,
    batch_size: int = 256,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Predict softmax probabilities row-by-row in frozen order."""

    tokenized = tokenize_frame(frame, "inference", config, tokenizer)
    model.eval()
    model.to(device)
    outputs: list[np.ndarray] = []
    for start in range(0, len(tokenized), batch_size):
        stop = start + batch_size
        batch_ids = tokenized.input_ids[start:stop].to(device)
        batch_mask = tokenized.attention_mask[start:stop].to(device)
        logits = model(batch_ids, batch_mask)
        outputs.append(torch.softmax(logits.float(), dim=-1).cpu().numpy())
    probabilities = np.concatenate(outputs, axis=0)
    return probabilities, probabilities.argmax(axis=1), tokenized.row_ids


def _measure_latency(
    model: torch.nn.Module,
    tokenizer: object,
    texts: list[str],
    device: torch.device,
    warmup: int,
    iterations: int,
) -> dict[str, float]:
    """Per-URL latency (batch size 1) on the given device."""

    model.eval()
    model.to(device)
    samples = [texts[index % len(texts)] for index in range(warmup + iterations)]
    durations: list[float] = []
    with torch.no_grad():
        for index, text in enumerate(samples):
            encoded = tokenizer(text, return_tensors="pt", truncation=True, max_length=64)
            input_ids = encoded["input_ids"].to(device)
            attention_mask = encoded["attention_mask"].to(device)
            if device.type == "cuda":
                torch.cuda.synchronize()
            started = time.perf_counter()
            model(input_ids, attention_mask)
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


def _update_comparison(path: Path, row: dict[str, object]) -> None:
    """Upsert the URLBERT row into the shared baseline comparison table."""

    frame = pd.read_csv(path) if path.exists() else pd.DataFrame(columns=COMPARISON_COLUMNS)
    for column in COMPARISON_COLUMNS:
        if column not in frame.columns:
            frame[column] = pd.NA
    frame = frame[~((frame["Model"] == row["Model"]) & (frame["Dataset View"] == row["Dataset View"]))]
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([frame, pd.DataFrame([row])], ignore_index=True)[COMPARISON_COLUMNS].to_csv(path, index=False)


def evaluate(
    config_path: str | Path | None = None,
    *,
    config: URLBERTConfig | None = None,
) -> dict[str, Any]:
    """Run the single official URLBERT Test evaluation."""

    configure_logging()
    urlbert = config or load_urlbert_config(config_path)
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available; refusing to run the official evaluation on CPU")
    device = torch.device("cuda")

    manifest = verify_frozen_test_manifest(urlbert, verify_test_files=True)
    test_frame = load_frozen_split(urlbert, "test")
    contract = validate_frozen_contract(
        urlbert,
        {**{split: load_frozen_split(urlbert, split) for split in ("train", "validation")}, "test": test_frame},
        require_all_splits=True,
    )

    checkpoint_dir = urlbert.path("checkpoint_dir")
    best_path = checkpoint_dir / "best.pt"
    metadata_path = checkpoint_dir / "metadata.json"
    if not best_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("Train the URLBERT model before evaluation")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("datasetVersion") != urlbert.dataset_version:
        raise DatasetContractError("URLBERT checkpoint was trained on a different dataset version")
    if metadata.get("testManifestSHA256") != urlbert.raw.get("expected_test_manifest_sha256"):
        raise DatasetContractError("URLBERT checkpoint is not bound to the current Test Manifest")
    if metadata.get("labelMapping") != urlbert.label_mapping:
        raise DatasetContractError("URLBERT label mapping differs from the frozen three-class scheme")

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(urlbert.base_model, revision=urlbert.base_model_revision)
    model, payload = load_checkpoint(best_path, urlbert.base_model, urlbert.base_model_revision)
    if payload.get("validation_macro_f1") != metadata.get("bestValidationMacroF1"):
        LOGGER.warning("Checkpoint metadata and training metadata disagree on validation macro F1")

    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    probabilities, predicted, row_ids = predict_frame(model, test_frame, urlbert, tokenizer, device)
    y_true = np.array([urlbert.label_mapping[str(value)] for value in test_frame["label"].astype(str)])
    label_names = urlbert.label_names
    calculator = calculate_binary_metrics if urlbert.num_classes == 2 else calculate_metrics
    metrics = calculator(y_true, predicted, probabilities)

    metrics_dir = urlbert.path("metrics")
    figures_dir = urlbert.path("figures")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        **metrics,
        "datasetVersion": urlbert.dataset_version,
        "datasetView": urlbert.dataset_view,
        "task": "binary_phishing" if urlbert.num_classes == 2 else "three_class",
        "testManifestSHA256": sha256_file(urlbert.raw_path("test_manifest")),
        "testSetSHA256": manifest["views"][urlbert.manifest_view]["sha256"],
        "rowCount": int(len(test_frame)),
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "labelNames": label_names,
        "modelVersion": metadata.get("modelVersion"),
    }
    (metrics_dir / "test_metrics.json").write_text(
        json.dumps(metrics_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    plot_confusion_matrix(
        metrics["confusion_matrix"], label_names, figures_dir / "confusion_matrix.png"
    )

    predictions_columns: dict[str, object] = {
        "rowId": row_ids,
        "text": test_frame[urlbert.text_column].astype(str),
        "registrableDomain": test_frame["registrable_domain"].astype(str),
        "label": test_frame["label"].astype(str),
        "source": test_frame["source"].astype(str) if "source" in test_frame else "",
        "predicted": [label_names[index] for index in predicted],
        "probabilityBenign": probabilities[:, 0],
        "probabilityPhishing": probabilities[:, 1],
    }
    if probabilities.shape[1] > 2:
        predictions_columns["probabilityMalware"] = probabilities[:, 2]
    predictions_frame = pd.DataFrame(predictions_columns)
    predictions_frame.to_csv(metrics_dir / "test_predictions.csv", index=False)

    texts = test_frame[urlbert.text_column].astype(str).tolist()
    benchmark = urlbert.benchmark
    latency_gpu = _measure_latency(
        model,
        tokenizer,
        texts,
        device,
        int(benchmark.get("warmup_iterations", 20)),
        int(benchmark.get("timed_iterations", 200)),
    )
    peak_vram = int(torch.cuda.max_memory_allocated()) if torch.cuda.is_available() else 0
    model_size = best_path.stat().st_size

    metadata.setdefault("metrics", {})["test"] = metrics
    metadata["testMetrics"] = metrics_payload
    metadata["modelSizeBytes"] = model_size
    metadata["evaluation"] = {
        "evaluatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "latencyGpuMs": latency_gpu,
        "peakVramBytes": peak_vram,
        "testRowCount": int(len(test_frame)),
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
    }
    metadata["datasetContract"] = contract
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    model_label = str(
        urlbert.raw.get("comparison_urlbert_model", "URLBERT Domain Only")
    )
    if urlbert.num_classes == 2:
        row = {
            "Model": model_label,
            "Dataset View": urlbert.dataset_view.upper(),
            "Task": "binary_phishing",
            "Accuracy": metrics["accuracy"],
            "Precision": metrics["precision"],
            "Recall": metrics["recall"],
            "F1": metrics["f1"],
            "Specificity": metrics["specificity"],
            "Benign FPR": metrics["false_positive_rate"],
            "False Negative Rate": metrics["false_negative_rate"],
            "AUROC": metrics["auroc"],
            "AUPRC": metrics["auprc"],
            "Experiment Type": metadata.get("experimentType"),
            "Dataset Version": metadata.get("datasetVersion"),
            "Model Version": metadata.get("modelVersion"),
            "Model SHA-256": metadata.get("modelSHA256"),
            "Test Manifest SHA-256": sha256_file(urlbert.raw_path("test_manifest")),
            "Test Set SHA-256": manifest["views"][urlbert.manifest_view]["sha256"],
        }
    else:
        row = {
            "Model": model_label,
            "Dataset View": urlbert.dataset_view.upper(),
            "Accuracy": metrics["accuracy"],
            "Macro Precision": metrics["macro_precision"],
            "Macro Recall": metrics["macro_recall"],
            "Macro F1": metrics["macro_f1"],
            "Weighted F1": metrics["weighted_f1"],
            "Phishing Recall": metrics["phishing_recall"],
            "Malware Recall": metrics["malware_recall"],
            "Benign FPR": metrics["benign_false_positive_rate"],
            "Malicious FNR": metrics["malicious_false_negative_rate"],
            "AUROC": metrics["auroc_ovr_macro"],
            "AUPRC": metrics["auprc_ovr_macro"],
            "Experiment Type": metadata.get("experimentType"),
            "Dataset Version": metadata.get("datasetVersion"),
            "Model Version": metadata.get("modelVersion"),
            "Model SHA-256": metadata.get("modelSHA256"),
            "Test Manifest SHA-256": sha256_file(urlbert.raw_path("test_manifest")),
            "Test Set SHA-256": manifest["views"][urlbert.manifest_view]["sha256"],
        }
    _update_comparison(urlbert.path("metrics").parents[1] / "baseline_comparison.csv", row)

    LOGGER.info(
        "URLBERT test accuracy %.6f; %s %.6f",
        metrics["accuracy"],
        "F1" if urlbert.num_classes == 2 else "macro F1",
        metrics["f1"] if urlbert.num_classes == 2 else metrics["macro_f1"],
    )
    return metrics_payload


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate the URLBERT classifier once on the frozen Test Set")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(args.config), ensure_ascii=False, indent=2))
    except (DatasetContractError, FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
