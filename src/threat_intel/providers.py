"""Threat Intelligence providers backed by locally acquired snapshots.

The acquisition pipeline already stores immutable source snapshots. These
providers build an in-memory index from those snapshots so that lookups work
offline, which is the same shape the future Android runtime needs.

A provider that cannot read its snapshot returns `UNAVAILABLE`; a provider that
reads its snapshot but does not contain the indicator returns `UNKNOWN`. Those
two states are never collapsed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

import pandas as pd

from src.data.hosttype import classify_host_type
from src.threat_intel.contract import (
    ConfidenceType,
    ProviderName,
    ThreatIntelligenceResult,
    ThreatStatus,
    ThreatType,
    UNKNOWN_RESULT,
    provider_error,
    unavailable,
)


class ThreatIntelligenceProvider(Protocol):
    """Interface every threat intelligence provider implements."""

    name: ProviderName

    def is_available(self) -> bool: ...

    def lookup(self, indicator: str) -> ThreatIntelligenceResult: ...


@dataclass(frozen=True)
class _IndexEntry:
    threat_type: ThreatType
    source_timestamp: str | None


def _normalise(value: str) -> str:
    return str(value).strip().strip(".").lower()


class SnapshotIndexProvider:
    """Common behaviour for providers backed by a local snapshot index."""

    name: ProviderName = ProviderName.URLHAUS
    threat_type: ThreatType = ThreatType.MALWARE

    def __init__(self, rows: Sequence[tuple[str, str | None]] | None = None, *, detail: str = "") -> None:
        self._index: dict[str, _IndexEntry] = {}
        self._available = rows is not None
        self._detail = detail
        if rows:
            for indicator, timestamp in rows:
                key = _normalise(indicator)
                if key:
                    self._index.setdefault(key, _IndexEntry(self.threat_type, timestamp))

    def is_available(self) -> bool:
        return self._available

    def index_size(self) -> int:
        return len(self._index)

    def lookup(self, indicator: str) -> ThreatIntelligenceResult:
        if not self._available:
            return unavailable(self.name, self._detail or "snapshot index is not available")
        key = _normalise(indicator)
        if not key:
            return provider_error(self.name, "empty indicator")
        entry = self._index.get(key)
        if entry is not None:
            confidence = (
                ConfidenceType.EXACT_MATCH
                if classify_host_type(key) != "DOMAIN"
                else ConfidenceType.DOMAIN_MATCH
            )
            return ThreatIntelligenceResult(
                status=ThreatStatus.KNOWN_MALICIOUS,
                threat_type=entry.threat_type,
                providers=(self.name,),
                confidence_type=confidence,
                matched_indicator=key,
                source_timestamp=entry.source_timestamp,
                detail=f"{self.name.value} snapshot contains this indicator",
            )
        return UNKNOWN_RESULT

    def lookup_url(self, hostname: str, registrable_domain: str) -> ThreatIntelligenceResult:
        """Match the full hostname first, then the registrable domain."""

        if not self._available:
            return unavailable(self.name, self._detail or "snapshot index is not available")
        for candidate in (_normalise(hostname), _normalise(registrable_domain)):
            if not candidate:
                continue
            entry = self._index.get(candidate)
            if entry is not None:
                return ThreatIntelligenceResult(
                    status=ThreatStatus.KNOWN_MALICIOUS,
                    threat_type=entry.threat_type,
                    providers=(self.name,),
                    confidence_type=ConfidenceType.DOMAIN_MATCH,
                    matched_indicator=candidate,
                    source_timestamp=entry.source_timestamp,
                    detail=f"{self.name.value} snapshot contains this domain",
                )
        return UNKNOWN_RESULT


class UrlHausProvider(SnapshotIndexProvider):
    """URLhaus malware URL/domain evidence."""

    name = ProviderName.URLHAUS
    threat_type = ThreatType.MALWARE

    @classmethod
    def from_snapshot_dir(cls, raw_root: str | Path) -> "UrlHausProvider":
        directory = Path(raw_root) / "malware"
        if not directory.exists():
            return cls(None, detail="URLhaus snapshot directory is missing")
        rows: list[tuple[str, str | None]] = []
        for path in sorted(directory.glob("urlhaus_*.csv")):
            frame = pd.read_csv(path, dtype=str, low_memory=False)
            if "url" not in frame.columns:
                continue
            hosts = (
                frame["url"]
                .astype(str)
                .str.extract(r"^[a-zA-Z]+://([^/?#]+)")[0]
                .str.replace(r":\d+$", "", regex=True)
            )
            timestamps = frame["collected_at"].astype(str) if "collected_at" in frame else None
            for position, host in enumerate(hosts):
                if isinstance(host, str) and host:
                    rows.append((host, None if timestamps is None else str(timestamps.iloc[position])))
        if not rows:
            return cls(None, detail="URLhaus snapshot contains no usable indicators")
        return cls(rows)


class ThreatFoxProvider(SnapshotIndexProvider):
    """ThreatFox domain payload-delivery evidence."""

    name = ProviderName.THREATFOX
    threat_type = ThreatType.MALWARE

    @classmethod
    def from_snapshot_dir(cls, raw_root: str | Path) -> "ThreatFoxProvider":
        directory = Path(raw_root) / "malware"
        if not directory.exists():
            return cls(None, detail="ThreatFox snapshot directory is missing")
        rows: list[tuple[str, str | None]] = []
        for path in sorted(directory.glob("threatfox_*.csv")):
            frame = pd.read_csv(path, dtype=str, low_memory=False)
            if "url" not in frame.columns:
                continue
            hosts = frame["url"].astype(str).str.extract(r"^https?://([^/?#]+)")[0]
            timestamps = frame["first_seen"].astype(str) if "first_seen" in frame else None
            for position, host in enumerate(hosts):
                if isinstance(host, str) and host:
                    rows.append((host, None if timestamps is None else str(timestamps.iloc[position])))
        if not rows:
            return cls(None, detail="ThreatFox snapshot contains no usable indicators")
        return cls(rows)


def default_providers(raw_root: str | Path) -> list[ThreatIntelligenceProvider]:
    return [
        UrlHausProvider.from_snapshot_dir(raw_root),
        ThreatFoxProvider.from_snapshot_dir(raw_root),
    ]
