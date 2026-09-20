"""Build dataset-v1.3.0: binary BENIGN/PHISHING dataset with a frozen Test Set."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.dataset_v13 import build_dataset_v13
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(description="Build dataset-v1.3.0 binary phishing dataset")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        metadata = build_dataset_v13(args.config)
        summary = {
            "datasetVersion": metadata["datasetVersion"],
            "labelMapping": metadata["labelMapping"],
            "viewDistribution": metadata["viewDistribution"],
            "viewSourceDistribution": metadata["viewSourceDistribution"],
            "splits": {
                key: metadata["splits"][key]
                for key in ("trainSize", "validationSize", "testSize", "domainLeakage")
            },
            "crossSourceConflictAudit": metadata["crossSourceConflictAudit"],
            "testManifestSHA256": metadata["testManifestSHA256"],
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    except (OSError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
