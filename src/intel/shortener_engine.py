"""Offline shortener detection (ShortenerDetectionEngine).

A shortener match is an opacity signal: the final destination cannot be known
without expanding the link, and this project never expands links automatically.
The policy may raise a review for a shortener, but a shortener alone must never
produce a block.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from src.data.normalizer import NormalizedURL
from src.intel.catalogs import SHORTENER_DOMAINS


@dataclass(frozen=True)
class ShortenerAssessment:
    detected: bool
    domain: str | None

    def to_features(self) -> dict[str, float]:
        return {"shortener_detected": 1.0 if self.detected else 0.0}

    def availability(self) -> dict[str, bool]:
        return {"shortener_detected": True}

    def to_dict(self) -> dict[str, Any]:
        return {"detected": self.detected, "domain": self.domain}


class ShortenerDetectionEngine:
    def __init__(self, domains: Iterable[str] = SHORTENER_DOMAINS) -> None:
        self._domains = tuple(sorted({domain.lower() for domain in domains}))

    def assess(self, url: NormalizedURL) -> ShortenerAssessment:
        hostname = url.hostname.lower()
        registrable = url.registrable_domain.lower()
        for domain in self._domains:
            if registrable == domain or hostname == domain or hostname.endswith("." + domain):
                return ShortenerAssessment(True, domain)
        return ShortenerAssessment(False, None)
