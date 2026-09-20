from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def record_acquisition_status(
    report_path: str | Path,
    source: str,
    status: str,
    detail: str,
    snapshot_id: str | None = None,
) -> None:
    path = Path(report_path)
    if path.exists():
        report = json.loads(path.read_text(encoding="utf-8"))
    else:
        report = {"sources": {}}
    report["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["sources"][source] = {
        "status": status,
        "detail": detail,
        "snapshot_id": snapshot_id,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
