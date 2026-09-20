"""Build the TI Bundle v1 asset for the Android deployment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.deployment.ti_bundle_builder import build_bundle_from_frozen_snapshot, write_bundle_asset

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the TI Bundle v1 asset.")
    parser.add_argument("--output", default=str(ROOT / "deployment" / "android" / "v2"))
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    summary = write_bundle_asset(args.output, build_bundle_from_frozen_snapshot())
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
