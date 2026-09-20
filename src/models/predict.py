from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.data.normalizer import normalize_url
from src.features.extractor import extract_features
from src.features.schema import FEATURE_NAMES
from src.utils.config import load_config, project_path

CLASS_NAMES = ["BENIGN", "PHISHING", "MALWARE"]


def predict_url(url: str, config_path: str | Path | None = None, view: str | None = None) -> dict[str, object]:
    config = load_config(config_path)
    model_path = project_path(config["paths"]["model_dir"]) / "model.txt"
    if view:
        model_path = project_path(config["paths"]["model_dir"]) / view / "model.txt"
    if not model_path.exists():
        raise FileNotFoundError("No trained model. Build a formal dataset and train first.")
    parsed = normalize_url(url)
    features = extract_features(parsed)
    booster = lgb.Booster(model_str=model_path.read_text(encoding="utf-8"))
    values = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
    probabilities = np.asarray(booster.predict(values))[0]
    predicted = int(probabilities.argmax())
    return {
        "resultType": "Model prediction",
        "normalizedUrl": parsed.normalized_url,
        "registrableDomain": parsed.registrable_domain,
        "features": features,
        "probabilities": {name: float(probabilities[index]) for index, name in enumerate(CLASS_NAMES)},
        "predictedClass": CLASS_NAMES[predicted],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run static model prediction for one URL string")
    parser.add_argument("url")
    parser.add_argument("--config", default=None)
    parser.add_argument("--view", choices=["domain_only", "full_url"], default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(predict_url(args.url, args.config, args.view), ensure_ascii=False, indent=2))
    except (FileNotFoundError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
