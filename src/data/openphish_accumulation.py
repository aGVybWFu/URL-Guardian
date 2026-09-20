"""OpenPhish snapshot accumulation with cross-snapshot deduplication.

The OpenPhish community feed is a rolling window, so the same URL reappears on
many days. Accumulating snapshots must therefore count each distinct URL and each
distinct registrable domain once, otherwise repeated appearances would inflate
the dataset.

This module records the per-snapshot evidence (date, SHA-256, record count) so an
accumulated set can always be traced back to the snapshots that produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from src.data.normalizer import URLNormalizationError, normalize_url
from src.data.snapshot import sha256_file


@dataclass(frozen=True)
class SnapshotEvidence:
    """Provenance for one OpenPhish snapshot."""

    snapshot_date: str
    path: str
    sha256: str
    record_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshotDate": self.snapshot_date,
            "file": self.path,
            "sha256": self.sha256,
            "recordCount": self.record_count,
        }


@dataclass
class AccumulationResult:
    """Deduplicated union of several OpenPhish snapshots."""

    frame: pd.DataFrame
    snapshots: list[SnapshotEvidence] = field(default_factory=list)
    total_raw_records: int = 0
    unique_normalized_urls: int = 0
    unique_registrable_domains: int = 0
    duplicate_url_occurrences: int = 0
    invalid_records: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshotCount": len(self.snapshots),
            "snapshots": [snapshot.to_dict() for snapshot in self.snapshots],
            "totalRawRecords": self.total_raw_records,
            "uniqueNormalizedUrls": self.unique_normalized_urls,
            "uniqueRegistrableDomains": self.unique_registrable_domains,
            "duplicateUrlOccurrences": self.duplicate_url_occurrences,
            "invalidRecords": self.invalid_records,
            "deduplicationRule": (
                "A URL that reappears in later snapshots is counted once. Domain-level counts "
                "collapse all URLs that share a registrable domain."
            ),
        }


def discover_snapshots(raw_root: str | Path, source: str = "openphish") -> list[SnapshotEvidence]:
    """List the dated OpenPhish snapshots present in the raw snapshot catalog."""

    root = Path(raw_root) / "snapshots"
    if not root.exists():
        return []
    evidence: list[SnapshotEvidence] = []
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        for candidate in sorted(directory.glob(f"{source}/*")):
            if not candidate.is_file() or candidate.name.endswith((".part", ".failures.jsonl")):
                continue
            evidence.append(
                SnapshotEvidence(
                    snapshot_date=directory.name,
                    path=candidate.as_posix(),
                    sha256=sha256_file(candidate),
                    record_count=_count_records(candidate),
                )
            )
    return evidence


def _count_records(path: Path) -> int:
    return sum(
        1
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def accumulate(
    snapshots: list[SnapshotEvidence],
    collected_at: str | None = None,
) -> AccumulationResult:
    """Union several OpenPhish snapshots with normalized URL and domain dedup."""

    records: list[dict[str, Any]] = []
    invalid = 0
    total_raw = 0
    for snapshot in snapshots:
        path = Path(snapshot.path)
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            total_raw += 1
            try:
                parsed = normalize_url(value)
            except (URLNormalizationError, TypeError, ValueError):
                invalid += 1
                continue
            records.append(
                {
                    "url": value,
                    "normalized_url": parsed.normalized_url,
                    "registrable_domain": parsed.registrable_domain,
                    "hostname": parsed.hostname,
                    "snapshot_date": snapshot.snapshot_date,
                    "snapshot_sha256": snapshot.sha256,
                }
            )
    frame = pd.DataFrame(records)
    if frame.empty:
        return AccumulationResult(
            frame=pd.DataFrame(
                columns=[
                    "url",
                    "normalized_url",
                    "registrable_domain",
                    "hostname",
                    "snapshot_date",
                    "snapshot_sha256",
                ]
            ),
            snapshots=snapshots,
            total_raw_records=total_raw,
            invalid_records=invalid,
        )

    frame = frame.sort_values(["normalized_url", "snapshot_date"]).reset_index(drop=True)
    unique = frame.drop_duplicates(subset=["normalized_url"], keep="first").reset_index(drop=True)
    duplicate_occurrences = int(len(frame) - len(unique))
    unique["label"] = "PHISHING"
    unique["source"] = "openphish"
    unique["collected_at"] = collected_at or unique["snapshot_date"]
    unique["label_confidence"] = "community_feed"
    unique["feed_type"] = "community"
    unique["first_snapshot_date"] = unique["snapshot_date"]
    return AccumulationResult(
        frame=unique,
        snapshots=snapshots,
        total_raw_records=total_raw,
        unique_normalized_urls=int(unique["normalized_url"].nunique()),
        unique_registrable_domains=int(unique["registrable_domain"].nunique()),
        duplicate_url_occurrences=duplicate_occurrences,
        invalid_records=invalid,
    )


def write_accumulation_report(result: AccumulationResult, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path
