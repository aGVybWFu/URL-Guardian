"""URLBERT prediction CLI for a single URL or domain string.

The input is parsed locally as a string only. It is normalized and reduced to
its registrable domain so that the model sees exactly the frozen `DOMAIN_ONLY`
representation. No network access is performed for the input.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import torch

from src.data.normalizer import normalize_url
from src.models.urlbert.config import URLBERTConfig, load_urlbert_config
from src.models.urlbert.dataset import verify_frozen_test_manifest
from src.models.urlbert.model import load_checkpoint
from src.utils.logging import get_logger

LOGGER = get_logger(__name__)


def _load_runtime(config: URLBERTConfig):
    from transformers import AutoTokenizer

    checkpoint_dir = config.path("checkpoint_dir")
    best_path = checkpoint_dir / "best.pt"
    metadata_path = checkpoint_dir / "metadata.json"
    if not best_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("No trained URLBERT checkpoint. Run the Phase 2 training first.")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    tokenizer = AutoTokenizer.from_pretrained(config.base_model, revision=config.base_model_revision)
    model, _ = load_checkpoint(best_path, config.base_model, config.base_model_revision)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    return model, tokenizer, metadata, device


def predict_text(text: str, config_path: str | Path | None = None) -> dict[str, Any]:
    """Predict one URL/domain string with the trained URLBERT classifier."""

    config = load_urlbert_config(config_path)
    verify_frozen_test_manifest(config, verify_test_files=False)
    parsed = normalize_url(text)
    domain = parsed.registrable_domain
    if not domain:
        raise ValueError("Input did not reduce to a registrable domain")
    model, tokenizer, metadata, device = _load_runtime(config)
    encoded = tokenizer(
        domain,
        return_tensors="pt",
        truncation=True,
        max_length=config.max_length,
    )
    with torch.no_grad():
        logits = model(encoded["input_ids"].to(device), encoded["attention_mask"].to(device))
        probabilities = torch.softmax(logits.float(), dim=-1).cpu().numpy()[0]
    predicted = int(np.argmax(probabilities))
    label_names = config.label_names
    return {
        "resultType": "Model Prediction",
        "input": text,
        "normalizedUrl": parsed.normalized_url,
        "registrableDomain": domain,
        "modelName": metadata.get("modelName"),
        "modelVersion": metadata.get("modelVersion"),
        "experimentId": metadata.get("experimentId"),
        "datasetVersion": metadata.get("datasetVersion"),
        "task": "binary_phishing" if config.num_classes == 2 else "three_class",
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "probabilities": {
            name: float(probabilities[index]) for index, name in enumerate(label_names)
        },
        "predictedClass": label_names[predicted],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a static URLBERT model prediction for one URL or domain string"
    )
    parser.add_argument("url")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(predict_text(args.url, args.config), ensure_ascii=False, indent=2))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
