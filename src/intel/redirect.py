"""Redirect observation contract.

Redirect features require observing the redirect chain, which static URL
analysis cannot do. The default resolver is `NoOpRedirectResolver`: it never
opens a connection and always reports `NOT_OBSERVED`, so the redirect features
are unavailable and the policy ignores them. A fixture resolver exists for
offline tests only; it is never wired to the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from src.data.normalizer import NormalizedURL

STATUS_NOT_OBSERVED = "NOT_OBSERVED"
STATUS_OBSERVED = "OBSERVED"


@dataclass(frozen=True)
class RedirectContext:
    status: str
    redirect_count: int = 0
    cross_domain_redirect: bool = False
    final_hostname: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {STATUS_NOT_OBSERVED, STATUS_OBSERVED}:
            raise ValueError("unknown redirect status")
        if self.redirect_count < 0:
            raise ValueError("redirect_count must not be negative")

    @classmethod
    def not_observed(cls) -> "RedirectContext":
        return cls(status=STATUS_NOT_OBSERVED)

    @property
    def observed(self) -> bool:
        return self.status == STATUS_OBSERVED

    def to_features(self) -> dict[str, float]:
        if not self.observed:
            return {}
        return {
            "redirect_count": float(self.redirect_count),
            "cross_domain_redirect": 1.0 if self.cross_domain_redirect else 0.0,
        }

    def availability(self) -> dict[str, bool]:
        return {"redirect_count": self.observed, "cross_domain_redirect": self.observed}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "redirectCount": self.redirect_count,
            "crossDomainRedirect": self.cross_domain_redirect,
            "finalHostname": self.final_hostname,
            "error": self.error,
        }


class RedirectResolver(Protocol):
    def resolve(self, url: NormalizedURL) -> RedirectContext: ...


class NoOpRedirectResolver:
    """Never performs network I/O; redirect evidence stays unavailable."""

    def resolve(self, url: NormalizedURL) -> RedirectContext:
        return RedirectContext.not_observed()


class FixtureRedirectResolver:
    """Offline-only resolver backed by a fixed mapping. For tests and demos."""

    def __init__(self, contexts: Mapping[str, RedirectContext]) -> None:
        self._contexts = dict(contexts)

    def resolve(self, url: NormalizedURL) -> RedirectContext:
        return self._contexts.get(url.normalized_url, RedirectContext.not_observed())
