"""Temporal threat-intelligence snapshot history.

A snapshot record is only created from data that was actually fetched on a
distinct date. The repository currently holds exactly one real snapshot
(`2026-09-20`); no duplicate copy is ever registered under a new date, and a
missing date stays missing.

Staleness is informational: an old snapshot is `STALE` or `OUTDATED`, never
`INVALID`, and never treated as safe.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "data" / "processed" / "ugdm-v1.0.0" / "threat_intel_snapshot.json"
HISTORY = ROOT / "deployment" / "ti" / "snapshot_history.json"
HISTORY_VERSION = "ti-snapshot-history-v1"
FRESH_DAYS = 30
STALE_DAYS = 180


@dataclass(frozen=True)
class SnapshotRecord:
    snapshot_id: str
    created_at: str
    indicator_count: int
    sha256: str
    sources: list[dict[str, Any]]
    source_timestamps: dict[str, str | None]
    previous_snapshot_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshotId": self.snapshot_id,
            "createdAt": self.created_at,
            "indicatorCount": self.indicator_count,
            "sha256": self.sha256,
            "sources": self.sources,
            "sourceTimestamps": self.source_timestamps,
            "previousSnapshotId": self.previous_snapshot_id,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _date_part(created_at: str) -> str:
    """Snapshot ids are date-scoped even when the source records a full timestamp."""

    return created_at.strip()[:10]


def snapshot_id_for(created_at: str) -> str:
    return f"ti-{_date_part(created_at)}"


def staleness(created_at: str, today: date | None = None) -> dict[str, Any]:
    """Informational age classification. Old never means invalid or safe."""

    reference = today or date.today()
    try:
        created = date.fromisoformat(_date_part(created_at))
    except ValueError:
        return {"ageDays": None, "status": "UNKNOWN", "freshDays": FRESH_DAYS, "staleDays": STALE_DAYS}
    age_days = (reference - created).days
    if age_days < 0:
        status = "UNKNOWN"
    elif age_days <= FRESH_DAYS:
        status = "FRESH"
    elif age_days <= STALE_DAYS:
        status = "STALE"
    else:
        status = "OUTDATED"
    return {"ageDays": age_days, "status": status, "freshDays": FRESH_DAYS, "staleDays": STALE_DAYS}


def build_record_from_frozen_snapshot(snapshot: Path = SNAPSHOT, previous_snapshot_id: str | None = None) -> SnapshotRecord:
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    created_at = str(payload["createdAt"])
    providers = payload.get("providers", [])
    source_timestamps = {
        str(provider.get("provider", "")): provider.get("sourceVersion") or provider.get("snapshotId")
        for provider in providers
    }
    return SnapshotRecord(
        snapshot_id=snapshot_id_for(created_at),
        created_at=created_at,
        indicator_count=int(payload["indicatorCount"]),
        sha256=sha256_file(snapshot),
        sources=[dict(provider) for provider in providers],
        source_timestamps=source_timestamps,
        previous_snapshot_id=previous_snapshot_id,
    )


def load_history(path: Path = HISTORY) -> dict[str, Any]:
    if not path.is_file():
        return {"historyVersion": HISTORY_VERSION, "records": []}
    return json.loads(path.read_text(encoding="utf-8"))


def register_record(record: SnapshotRecord, path: Path = HISTORY) -> tuple[dict[str, Any], bool]:
    """Append a record idempotently.

    Registration is keyed on the snapshot id and the snapshot file SHA-256, so
    re-running the workflow cannot duplicate a snapshot or fabricate a new date.
    """

    history = load_history(path)
    records = history.setdefault("records", [])
    for existing in records:
        if existing["snapshotId"] == record.snapshot_id:
            if existing["sha256"] != record.sha256:
                raise ValueError(f"snapshot {record.snapshot_id} already registered with a different digest")
            return history, False
    previous = records[-1]["snapshotId"] if records else None
    payload = record.to_dict()
    if payload["previousSnapshotId"] is None:
        payload["previousSnapshotId"] = previous
    records.append(payload)
    history["historyVersion"] = HISTORY_VERSION
    history["latestSnapshotId"] = records[-1]["snapshotId"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return history, True


def history_summary(history: dict[str, Any], today: date | None = None) -> dict[str, Any]:
    records = history.get("records", [])
    latest = records[-1] if records else None
    previous = records[-2] if len(records) > 1 else None
    return {
        "historyVersion": history.get("historyVersion", HISTORY_VERSION),
        "recordCount": len(records),
        "currentSnapshot": latest,
        "previousSnapshot": None if previous is None else {
            "snapshotId": previous["snapshotId"],
            "createdAt": previous["createdAt"],
            "sha256": previous["sha256"],
        },
        "staleness": staleness(latest["createdAt"], today) if latest else None,
    }
