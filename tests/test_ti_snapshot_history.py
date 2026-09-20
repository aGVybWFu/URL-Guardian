import json
from datetime import date
from pathlib import Path

import pytest

from src.deployment.ti_snapshot_history import (
    FRESH_DAYS,
    HISTORY_VERSION,
    STALE_DAYS,
    SnapshotRecord,
    build_record_from_frozen_snapshot,
    history_summary,
    load_history,
    register_record,
    snapshot_id_for,
    staleness,
)


def record(snapshot_id: str, created_at: str, digest: str) -> SnapshotRecord:
    return SnapshotRecord(
        snapshot_id=snapshot_id,
        created_at=created_at,
        indicator_count=2,
        sha256=digest,
        sources=[{"provider": "SYNTHETIC_TEST_FIXTURE"}],
        source_timestamps={"SYNTHETIC_TEST_FIXTURE": None},
        previous_snapshot_id=None,
    )


def test_frozen_snapshot_record_is_real_data_only() -> None:
    built = build_record_from_frozen_snapshot()
    assert built.snapshot_id == snapshot_id_for(built.created_at) == "ti-2026-09-20"
    assert built.created_at.startswith("2026-09-20")
    assert built.indicator_count == 7833
    assert len(built.sha256) == 64
    assert built.previous_snapshot_id is None


def test_registration_is_idempotent(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    first, added_first = register_record(record("ti-2026-09-20", "2026-09-20", "a" * 64), history_path)
    second, added_second = register_record(record("ti-2026-09-20", "2026-09-20", "a" * 64), history_path)
    assert added_first and not added_second
    assert len(first["records"]) == len(second["records"]) == 1
    assert second["latestSnapshotId"] == "ti-2026-09-20"


def test_same_id_with_different_digest_is_rejected(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    register_record(record("ti-2026-09-20", "2026-09-20", "a" * 64), history_path)
    with pytest.raises(ValueError):
        register_record(record("ti-2026-09-20", "2026-09-20", "b" * 64), history_path)


def test_previous_snapshot_linkage(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    register_record(record("ti-2026-09-20", "2026-09-20", "a" * 64), history_path)
    history, added = register_record(record("ti-2026-10-25", "2026-10-25", "b" * 64), history_path)
    assert added
    assert history["records"][1]["previousSnapshotId"] == "ti-2026-09-20"
    summary = history_summary(history, today=date(2026, 10, 26))
    assert summary["recordCount"] == 2
    assert summary["currentSnapshot"]["snapshotId"] == "ti-2026-10-25"
    assert summary["previousSnapshot"]["snapshotId"] == "ti-2026-09-20"
    assert summary["staleness"]["status"] == "FRESH"


def test_staleness_is_informational_not_invalidating() -> None:
    fresh = staleness("2026-09-20", today=date(2026, 9, 25))
    assert fresh["status"] == "FRESH" and fresh["ageDays"] == 5
    stale = staleness("2026-09-20", today=date(2026, 12, 1))
    assert stale["status"] == "STALE"
    outdated = staleness("2026-09-20", today=date(2027, 6, 1))
    assert outdated["status"] == "OUTDATED"
    assert stale["freshDays"] == FRESH_DAYS and stale["staleDays"] == STALE_DAYS
    assert staleness("not-a-date")["status"] == "UNKNOWN"


def test_missing_history_file_is_empty_not_guessed(tmp_path: Path) -> None:
    history = load_history(tmp_path / "missing.json")
    assert history["historyVersion"] == HISTORY_VERSION
    assert history["records"] == []


def test_repository_history_contains_only_real_snapshots() -> None:
    history_path = Path(__file__).resolve().parents[1] / "deployment" / "ti" / "snapshot_history.json"
    history = json.loads(history_path.read_text(encoding="utf-8"))
    assert history["historyVersion"] == HISTORY_VERSION
    ids = [item["snapshotId"] for item in history["records"]]
    assert ids == ["ti-2026-09-20"], "no snapshot may be registered under a date that was never fetched"
    assert history["records"][0]["indicatorCount"] == 7833
