"""Frozen Threat Intelligence snapshot for reproducible UGDM evaluation.

Live provider queries would make the same Test Set produce different results as
feeds update. UGDM therefore evaluates against a frozen snapshot built from the
immutable raw snapshots, and records enough provenance to reproduce it.

Indicators are stored as SHA-256 digests so the processed artifact can be shared
without embedding raw malicious hostnames.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.data.snapshot import load_snapshot_catalog, sha256_file
from src.threat_intel import ProviderName, ThreatIntelligenceService


def indicator_digest(value: str) -> str:
    return hashlib.sha256(str(value).strip().strip(".").lower().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SnapshotSource:
    """Provenance for one provider inside the frozen snapshot."""

    provider: str
    snapshot_id: str
    source_version: str | None
    file: str
    sha256: str
    record_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "snapshotId": self.snapshot_id,
            "sourceVersion": self.source_version,
            "file": self.file,
            "sha256": self.sha256,
            "recordCount": self.record_count,
        }


class FrozenThreatIntelSnapshot:
    """A read-only indicator index with recorded provenance."""

    def __init__(self, digests: set[str], payload: dict[str, Any]) -> None:
        self._digests = set(digests)
        self._payload = payload

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self._payload)

    @property
    def indicator_count(self) -> int:
        return len(self._digests)

    def contains(self, indicator: str) -> bool:
        return indicator_digest(indicator) in self._digests

    @classmethod
    def from_service(cls, service: ThreatIntelligenceService, raw_root: str | Path) -> "FrozenThreatIntelSnapshot":
        digests: set[str] = set()
        sources: list[SnapshotSource] = []
        catalog = {
            str(entry.get("source")): entry
            for snapshot in load_snapshot_catalog(raw_root)
            for entry in snapshot.get("sources", [])
        }
        for provider in service.providers:
            name = provider.name.value
            catalog_key = "urlhaus" if name == ProviderName.URLHAUS.value else "threatfox"
            entry = catalog.get(catalog_key)
            for indicator in getattr(provider, "_index", {}):
                digests.add(indicator_digest(indicator))
            if entry is not None:
                sources.append(
                    SnapshotSource(
                        provider=name,
                        snapshot_id=str(entry.get("snapshot_id") or ""),
                        source_version=entry.get("source_version"),
                        file=str(entry.get("file")),
                        sha256=str(entry.get("sha256")),
                        record_count=int(entry.get("record_count", 0)),
                    )
                )
        payload = {
            "snapshotType": "frozen_threat_intelligence_snapshot",
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "indicatorCount": len(digests),
            "indicatorDigestAlgorithm": "sha256",
            "providers": [source.to_dict() for source in sources],
            "providerStatus": service.provider_status(),
            "reproducibilityNote": (
                "Indicators are frozen from the immutable raw snapshots so repeated UGDM evaluation "
                "returns the same result. Raw indicators are stored only as SHA-256 digests."
            ),
        }
        return cls(digests, payload)

    @classmethod
    def load(cls, path: str | Path) -> "FrozenThreatIntelSnapshot":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        digests = set(payload.get("indicatorDigests", []))
        return cls(digests, payload)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {**self._payload, "indicatorDigests": sorted(self._digests)}
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return target

    def digest_sha256(self) -> str:
        joined = "\n".join(sorted(self._digests))
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def service(self) -> ThreatIntelligenceService:
        """Rebuild a service whose providers answer from this frozen index."""

        from src.threat_intel.providers import SnapshotIndexProvider
        from src.threat_intel.contract import ProviderName as Name

        class _Frozen(SnapshotIndexProvider):
            pass

        providers = []
        for source in self._payload.get("providers", []):
            provider_name = source["provider"]
            rows = []
            # The frozen index is digest-only, so the provider answers via the
            # digest path below instead of rebuilding raw indicators.
            providers.append(_Frozen(None, detail=f"frozen snapshot for {provider_name}"))
        service = ThreatIntelligenceService(providers)
        service._frozen_snapshot = self  # type: ignore[attr-defined]
        return service

    def lookup_digest(self, indicator: str) -> bool:
        return self.contains(indicator)


def build_frozen_snapshot(raw_root: str | Path, output: str | Path) -> FrozenThreatIntelSnapshot:
    service = ThreatIntelligenceService.from_raw_root(raw_root)
    snapshot = FrozenThreatIntelSnapshot.from_service(service, raw_root)
    snapshot.save(output)
    return snapshot


def snapshot_evidence(path: str | Path) -> dict[str, Any]:
    """Metadata block embedded in the UGDM dataset and model metadata."""

    target = Path(path)
    payload = json.loads(target.read_text(encoding="utf-8"))
    return {
        "file": target.as_posix(),
        "sha256": sha256_file(target),
        "createdAt": payload.get("createdAt"),
        "indicatorCount": payload.get("indicatorCount"),
        "providers": payload.get("providers", []),
    }
