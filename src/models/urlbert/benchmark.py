"""Desktop research benchmark: LightGBM vs URLBERT on the frozen Test inputs.

Latency values are measured on the local workstation and are explicitly a
Desktop Research Benchmark. They must never be presented as Android or
deployment latency.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any, Callable

import lightgbm as lgb
import numpy as np
import pandas as pd
import torch

from src.data.snapshot import sha256_file
from src.features.extractor import extract_feature_frame
from src.features.schema import FEATURE_NAMES
from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.dataset import load_frozen_split, validate_frozen_contract, verify_frozen_test_manifest
from src.models.urlbert.model import load_checkpoint
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def _percentiles(durations: list[float]) -> dict[str, float]:
    series = pd.Series(durations)
    return {
        "averageMs": float(series.mean()),
        "p50Ms": float(series.quantile(0.50)),
        "p95Ms": float(series.quantile(0.95)),
        "minMs": float(series.min()),
        "maxMs": float(series.max()),
    }


def _measure(call: Callable[[int], Any], warmup: int, iterations: int) -> dict[str, float]:
    durations: list[float] = []
    for index in range(warmup + iterations):
        started = time.perf_counter()
        call(index)
        elapsed = (time.perf_counter() - started) * 1000.0
        if index >= warmup:
            durations.append(elapsed)
    return _percentiles(durations)


def _peak_rss_bytes() -> int | None:
    try:
        import psutil
    except ImportError:
        return None
    return int(psutil.Process().memory_info().rss)


def run_benchmark(config_path: str | Path | None = None) -> dict[str, Any]:
    """Measure size and per-URL latency for both official models."""

    configure_logging()
    urlbert_config = load_urlbert_config(config_path)
    lightgbm_config = load_config()
    verify_frozen_test_manifest(urlbert_config, verify_test_files=True)
    test_frame = load_frozen_split(urlbert_config, "test")
    contract = validate_frozen_contract(
        urlbert_config,
        {
            **{split: load_frozen_split(urlbert_config, split) for split in ("train", "validation")},
            "test": test_frame,
        },
        require_all_splits=True,
    )
    benchmark_config = urlbert_config.benchmark
    warmup = int(benchmark_config.get("warmup_iterations", 20))
    iterations = int(benchmark_config.get("timed_iterations", 200))
    texts = test_frame[urlbert_config.text_column].astype(str).tolist()
    model_urls = test_frame["model_url"].astype(str).tolist()

    rows: list[dict[str, Any]] = []
    hardware = {
        "hardwareLabel": str(benchmark_config.get("hardware_label", "desktop-research-benchmark")),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "pythonVersion": platform.python_version(),
        "torchVersion": torch.__version__,
        "cudaAvailable": bool(torch.cuda.is_available()),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "cudaVersion": torch.version.cuda if torch.cuda.is_available() else None,
    }

    lightgbm_model_path = project_path(lightgbm_config["paths"]["model_dir"]) / "domain_only" / "model.txt"
    if lightgbm_model_path.exists():
        booster = lgb.Booster(model_str=lightgbm_model_path.read_text(encoding="utf-8"))
        baseline_features = extract_feature_frame(pd.Series(model_urls))
        lightgbm_latency = _measure(
            lambda index: booster.predict(baseline_features.iloc[[index % len(baseline_features)]][FEATURE_NAMES]),
            warmup,
            iterations,
        )
        rows.append(
            {
                "Model": "LightGBM Domain Only",
                "Dataset Version": urlbert_config.dataset_version,
                "Model Size Bytes": lightgbm_model_path.stat().st_size,
                "Parameter Count": None,
                "Compute Device": "cpu",
                **lightgbm_latency,
                "Peak VRAM Bytes": None,
                "Peak RSS Bytes": _peak_rss_bytes(),
                **hardware,
                "Notes": "Batch size 1, desktop CPU inference",
            }
        )
    else:
        LOGGER.warning("LightGBM baseline model not found; skipping its benchmark row")

    checkpoint_dir = urlbert_config.path("checkpoint_dir")
    best_path = checkpoint_dir / "best.pt"
    if best_path.exists() and torch.cuda.is_available():
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(
            urlbert_config.base_model, revision=urlbert_config.base_model_revision
        )
        model, _ = load_checkpoint(best_path, urlbert_config.base_model, urlbert_config.base_model_revision)
        device = torch.device("cuda")
        model.to(device)
        model.eval()
        encoded = tokenizer(
            texts, padding="max_length", truncation=True, max_length=urlbert_config.max_length, return_tensors="pt"
        )

        def run_urlbert(index: int) -> None:
            position = index % len(texts)
            input_ids = encoded["input_ids"][position : position + 1].to(device)
            attention_mask = encoded["attention_mask"][position : position + 1].to(device)
            with torch.no_grad():
                model(input_ids, attention_mask)
            torch.cuda.synchronize()

        torch.cuda.reset_peak_memory_stats()
        urlbert_latency = _measure(run_urlbert, warmup, iterations)
        rows.append(
            {
                "Model": "URLBERT Domain Only",
                "Dataset Version": urlbert_config.dataset_version,
                "Model Size Bytes": best_path.stat().st_size,
                "Parameter Count": int(model.total_parameters()),
                "Compute Device": "cuda",
                **urlbert_latency,
                "Peak VRAM Bytes": int(torch.cuda.max_memory_allocated()),
                "Peak RSS Bytes": _peak_rss_bytes(),
                **hardware,
                "Notes": "Batch size 1, GPU inference",
            }
        )
    else:
        LOGGER.warning("URLBERT checkpoint or CUDA unavailable; skipping its benchmark row")

    output_path = urlbert_config.path("metrics").parents[1] / "benchmark_comparison.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(rows)
    frame.to_csv(output_path, index=False)
    payload = {
        "hardware": hardware,
        "datasetVersion": urlbert_config.dataset_version,
        "testManifestSHA256": sha256_file(urlbert_config.raw_path("test_manifest")),
        "testRowCount": int(len(test_frame)),
        "rows": rows,
        "notes": "Desktop Research Benchmark only; not Android or deployment latency.",
        "datasetContract": contract,
    }
    (output_path.parent / "benchmark_comparison.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LOGGER.info("Wrote desktop benchmark to %s", output_path)
    return payload


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark LightGBM vs URLBERT on the frozen Test inputs")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(run_benchmark(args.config), ensure_ascii=False, indent=2))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
