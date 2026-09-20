"""Temporal holdout contract.

A real temporal holdout requires at least two distinct source snapshot dates so
that earlier data can feed Train/Validation and later data can be reserved as a
Temporal Test. This module defines and validates that contract. When the
repository does not yet hold enough distinct snapshot dates, the contract
reports `PENDING FUTURE SNAPSHOT` instead of fabricating a temporal split.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

TEMPORAL_STATUS_READY = "READY"
TEMPORAL_STATUS_PENDING = "PENDING FUTURE SNAPSHOT"

REQUIRED_TRAIN_DATES = 1
REQUIRED_TEST_DATES = 1


@dataclass(frozen=True)
class TemporalContract:
    """Machine-checkable description of the temporal holdout state."""

    status: str
    snapshot_dates: list[str] = field(default_factory=list)
    train_validation_dates: list[str] = field(default_factory=list)
    temporal_test_dates: list[str] = field(default_factory=list)
    rows_per_date: dict[str, int] = field(default_factory=dict)
    reason: str = ""

    @property
    def is_ready(self) -> bool:
        return self.status == TEMPORAL_STATUS_READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "snapshotDates": self.snapshot_dates,
            "trainValidationDates": self.train_validation_dates,
            "temporalTestDates": self.temporal_test_dates,
            "rowsPerDate": self.rows_per_date,
            "requiredTrainValidationDates": REQUIRED_TRAIN_DATES,
            "requiredTemporalTestDates": REQUIRED_TEST_DATES,
            "reason": self.reason,
            "rule": (
                "Earlier snapshot dates feed Train/Validation; strictly later snapshot dates are "
                "reserved as the Temporal Test. Dates must never be mixed across the boundary."
            ),
        }


def snapshot_dates_from_catalog(raw_root: str | Path) -> list[str]:
    """Return the distinct snapshot dates recorded in the raw snapshot catalog."""

    snapshots_root = Path(raw_root) / "snapshots"
    if not snapshots_root.exists():
        return []
    dates: set[str] = set()
    for metadata_path in sorted(snapshots_root.glob("*/snapshot_metadata.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        snapshot_id = str(metadata.get("snapshot_id", ""))
        if snapshot_id.startswith("snapshot-"):
            dates.add(snapshot_id[len("snapshot-") :])
        else:
            dates.add(metadata_path.parent.name)
    return sorted(dates)


def rows_per_collected_date(frame: pd.DataFrame, column: str = "collected_at") -> dict[str, int]:
    if column not in frame.columns:
        return {}
    values = frame[column].astype(str).str.slice(0, 10)
    values = values[values.str.match(r"^\d{4}-\d{2}-\d{2}$")]
    return {str(key): int(value) for key, value in values.value_counts().sort_index().items()}


def evaluate_temporal_contract(
    raw_root: str | Path,
    frame: pd.DataFrame | None = None,
) -> TemporalContract:
    """Assess whether a real temporal holdout can be built yet."""

    dates = snapshot_dates_from_catalog(raw_root)
    counts = rows_per_collected_date(frame) if frame is not None else {}
    if len(dates) < REQUIRED_TRAIN_DATES + REQUIRED_TEST_DATES:
        return TemporalContract(
            status=TEMPORAL_STATUS_PENDING,
            snapshot_dates=dates,
            rows_per_date=counts,
            reason=(
                f"Only {len(dates)} distinct snapshot date(s) exist. A temporal holdout needs at least "
                f"{REQUIRED_TRAIN_DATES + REQUIRED_TEST_DATES} so that a strictly later date can be "
                "reserved as the Temporal Test. No temporal split was fabricated."
            ),
        )
    ordered = sorted(dates)
    return TemporalContract(
        status=TEMPORAL_STATUS_READY,
        snapshot_dates=ordered,
        train_validation_dates=ordered[:-REQUIRED_TEST_DATES],
        temporal_test_dates=ordered[-REQUIRED_TEST_DATES:],
        rows_per_date=counts,
        reason="At least two distinct snapshot dates exist, so a temporal boundary can be defined.",
    )


def build_temporal_split(
    frame: pd.DataFrame,
    contract: TemporalContract,
    date_column: str = "collected_at",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split by snapshot date: earlier rows train, later rows become the Temporal Test.

    Raises when the contract is not ready. This function never reuses or reshapes
    the frozen domain-aware splits; it is an additional, independent evaluation.
    """

    if not contract.is_ready:
        raise RuntimeError(
            "Temporal holdout is not available: " + contract.reason
        )
    if date_column not in frame.columns:
        raise ValueError(f"Frame is missing the temporal column: {date_column}")
    dates = frame[date_column].astype(str).str.slice(0, 10)
    train_dates = set(contract.train_validation_dates)
    test_dates = set(contract.temporal_test_dates)
    train_mask = dates.isin(train_dates)
    test_mask = dates.isin(test_dates)
    if not test_mask.any():
        raise RuntimeError("No rows fall into the temporal test window")
    return frame[train_mask].copy(), frame[test_mask].copy()
