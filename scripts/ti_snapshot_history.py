"""Register or inspect the temporal threat-intelligence snapshot history."""

from __future__ import annotations

import argparse
import json
import sys

from src.deployment.ti_snapshot_history import (
    HISTORY,
    build_record_from_frozen_snapshot,
    history_summary,
    load_history,
    register_record,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="TI snapshot history workflow.")
    parser.add_argument("--register", action="store_true", help="register the frozen snapshot if it is not present")
    parser.add_argument("--status", action="store_true", help="print the current history summary")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.register:
        record = build_record_from_frozen_snapshot()
        _, added = register_record(record)
        print(json.dumps({"registered": added, "snapshotId": record.snapshot_id}, ensure_ascii=False))
    if args.status or not args.register:
        print(json.dumps(history_summary(load_history()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
