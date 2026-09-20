from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation.dataset_bias import audit_dataset_views
from src.utils.config import PROJECT_ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-run the dataset bias audit for both derived views")
    parser.add_argument("--views-dir", default=str(PROJECT_ROOT / "data" / "processed" / "views"))
    parser.add_argument("--output", default=str(PROJECT_ROOT / "reports" / "dataset_bias"))
    args = parser.parse_args()
    directory = Path(args.views_dir)
    views = {
        "domain_only": pd.read_csv(directory / "domain_only.csv"),
        "full_url": pd.read_csv(directory / "full_url.csv"),
    }
    print(json.dumps(audit_dataset_views(views, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
