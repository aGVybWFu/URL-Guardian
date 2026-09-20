"""Threat Intelligence domain model.

Design rules encoded here:

* `UNKNOWN` means "the intelligence sources did not contain this indicator". It
  must never be read as `SAFE`. There is deliberately no `SAFE` status: the
  absence of evidence is not evidence of safety.
* `UNAVAILABLE` and `ERROR` are provider health states, distinct from `UNKNOWN`.
  "The lookup ran and found nothing" is not the same as "the lookup could not run".
* Results carry evidence only. Credentials are never part of a result and are
  never persisted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatStatus(str, Enum):
    KNOWN_MALICIOUS = "KNOWN_MALICIOUS"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class ThreatType(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ProviderName(str, Enum):
    URLHAUS = "URLHAUS"
    THREATFOX = "THREATFOX"


class ConfidenceType(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    DOMAIN_MATCH = "DOMAIN_MATCH"
    UNKNOWN = "UNKNOWN"


SAFE_STATUSES: frozenset[ThreatStatus] = frozenset()
"""No status ever means safe. Kept explicit so callers cannot invent one."""


@dataclass(frozen=True)
class ThreatIntelligenceResult:
    """Evidence returned by one provider for one indicator."""

    status: ThreatStatus
    threat_type: ThreatType = ThreatType.UNKNOWN
    providers: tuple[ProviderName, ...] = field(default_factory=tuple)
    confidence_type: ConfidenceType = ConfidenceType.UNKNOWN
    matched_indicator: str | None = None
    source_timestamp: str | None = None
    detail: str = ""

    def is_known_malicious(self) -> bool:
        return self.status is ThreatStatus.KNOWN_MALICIOUS

    def is_unknown(self) -> bool:
        """True only for a completed lookup that found nothing."""

        return self.status is ThreatStatus.UNKNOWN

    def is_provider_problem(self) -> bool:
        return self.status in {ThreatStatus.UNAVAILABLE, ThreatStatus.ERROR}

    def is_safe(self) -> bool:
        """Always False. Provided so callers cannot silently assume safety."""

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "threatType": self.threat_type.value,
            "providers": [provider.value for provider in self.providers],
            "confidenceType": self.confidence_type.value,
            "matchedIndicator": self.matched_indicator,
            "sourceTimestamp": self.source_timestamp,
            "detail": self.detail,
            "safeStatusAvailable": False,
        }


UNKNOWN_RESULT = ThreatIntelligenceResult(
    status=ThreatStatus.UNKNOWN,
    detail="No approved threat intelligence source contained this indicator.",
)


def unavailable(provider: ProviderName, detail: str) -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        status=ThreatStatus.UNAVAILABLE,
        providers=(provider,),
        detail=detail,
    )


def provider_error(provider: ProviderName, detail: str) -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        status=ThreatStatus.ERROR,
        providers=(provider,),
        detail=detail,
    )


def merge(results: list[ThreatIntelligenceResult]) -> ThreatIntelligenceResult:
    """Combine provider results, preferring any confirmed malicious evidence.

    A confirmed hit from any provider wins. Otherwise a provider problem is
    surfaced before a plain miss, so a broken provider is never reported as a
    clean `UNKNOWN`.
    """

    if not results:
        return UNKNOWN_RESULT
    hits = [result for result in results if result.is_known_malicious()]
    if hits:
        best = hits[0]
        providers: list[ProviderName] = []
        for hit in hits:
            for provider in hit.providers:
                if provider not in providers:
                    providers.append(provider)
        confidence = best.confidence_type
        for hit in hits:
            if hit.confidence_type is ConfidenceType.EXACT_MATCH:
                confidence = ConfidenceType.EXACT_MATCH
                break
        return ThreatIntelligenceResult(
            status=ThreatStatus.KNOWN_MALICIOUS,
            threat_type=best.threat_type,
            providers=tuple(providers),
            confidence_type=confidence,
            matched_indicator=best.matched_indicator,
            source_timestamp=best.source_timestamp,
            detail=best.detail,
        )
    problems = [result for result in results if result.is_provider_problem()]
    if problems:
        return problems[0]
    return UNKNOWN_RESULT
