"""Threat Intelligence layer.

`lookup_url` answers one question: "is this indicator already known malicious
according to the approved intelligence sources?" A miss is `UNKNOWN`, never
`SAFE`. The layer is intentionally independent of any live network call so the
same contract can back an offline Android runtime later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from src.threat_intel.contract import (
    ProviderName,
    ThreatIntelligenceResult,
    ThreatStatus,
    merge,
)
from src.threat_intel.providers import (
    ThreatIntelligenceProvider,
    ThreatFoxProvider,
    UrlHausProvider,
    default_providers,
)

__all__ = [
    "ProviderName",
    "ThreatIntelligenceResult",
    "ThreatIntelligenceService",
    "ThreatIntelligenceProvider",
    "ThreatStatus",
    "ThreatFoxProvider",
    "UrlHausProvider",
    "default_providers",
]


class ThreatIntelligenceService:
    """Aggregate several providers into one evidence result."""

    def __init__(self, providers: Sequence[ThreatIntelligenceProvider]) -> None:
        self._providers = list(providers)

    @classmethod
    def from_raw_root(cls, raw_root: str | Path) -> "ThreatIntelligenceService":
        return cls(default_providers(raw_root))

    @property
    def providers(self) -> list[ThreatIntelligenceProvider]:
        return list(self._providers)

    def provider_status(self) -> dict[str, str]:
        return {
            provider.name.value: ("AVAILABLE" if provider.is_available() else "UNAVAILABLE")
            for provider in self._providers
        }

    def lookup_url(self, hostname: str, registrable_domain: str) -> ThreatIntelligenceResult:
        results: list[ThreatIntelligenceResult] = []
        for provider in self._providers:
            if hasattr(provider, "lookup_url"):
                results.append(provider.lookup_url(hostname, registrable_domain))  # type: ignore[attr-defined]
            else:
                results.append(provider.lookup(hostname))
        return merge(results)

    def lookup(self, indicator: str) -> ThreatIntelligenceResult:
        return merge([provider.lookup(indicator) for provider in self._providers])
