"""Offline brand-impersonation detection (BrandDetectionEngine).

The engine is a deterministic, catalog-based heuristic:

* Brand identity on the brand's own canonical domain is an explicit allow signal
  (`official_domain`), never an impersonation signal.
* A brand token on any other registrable domain is a domain mismatch.
* Confusable or punycode-obfuscated matches raise the risk score.
* Path/query-only mentions are weak evidence and never a mismatch.

Every decision here is explainable from the returned `BrandAssessment`; nothing
is learned and nothing is fetched from the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from src.data.normalizer import NormalizedURL
from src.intel.catalogs import BRAND_CATALOG, BrandEntry
from src.intel.confusables import idna_decode, label_tokens, looks_confusable, skeleton

LOCATION_REGISTRABLE = "registrable_domain"
LOCATION_SUBDOMAIN = "subdomain"
LOCATION_PATH = "path"

_SCORE_REGISTRABLE = 0.85
_SCORE_SUBDOMAIN = 0.70
_SCORE_PATH = 0.35
_CONFUSABLE_BONUS = 0.10


@dataclass(frozen=True)
class BrandMatch:
    brand_id: str
    matched_alias: str
    location: str
    confusable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "brandId": self.brand_id,
            "matchedAlias": self.matched_alias,
            "location": self.location,
            "confusable": self.confusable,
        }


@dataclass(frozen=True)
class BrandAssessment:
    detected: bool
    official_domain: bool
    domain_mismatch: bool
    risk_score: float
    brands: tuple[BrandMatch, ...]

    def to_features(self) -> dict[str, float]:
        return {
            "brand_detected": 1.0 if self.detected else 0.0,
            "brand_domain_mismatch": 1.0 if self.domain_mismatch else 0.0,
            "brand_risk_score": float(self.risk_score),
        }

    def availability(self) -> dict[str, bool]:
        return {"brand_detected": True, "brand_domain_mismatch": True, "brand_risk_score": True}

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "officialDomain": self.official_domain,
            "domainMismatch": self.domain_mismatch,
            "riskScore": self.risk_score,
            "brands": [match.to_dict() for match in self.brands],
        }


def _official_brand(hostname: str, registrable_domain: str, catalog: Iterable[BrandEntry]) -> BrandEntry | None:
    for entry in catalog:
        for domain in entry.canonical_domains:
            if registrable_domain == domain or hostname == domain or hostname.endswith("." + domain):
                return entry
    return None


def _alias_variants(alias: str) -> set[str]:
    return label_tokens(alias)


def _label_match(tokens: set[str], variants: set[str]) -> str | None:
    for alias in variants:
        if alias in tokens:
            return alias
    return None


class BrandDetectionEngine:
    def __init__(self, catalog: tuple[BrandEntry, ...] = BRAND_CATALOG) -> None:
        self._catalog = catalog
        self._variants: dict[str, set[str]] = {
            entry.brand_id: set().union(*(_alias_variants(alias) for alias in entry.aliases))
            for entry in catalog
        }

    def assess(self, url: NormalizedURL) -> BrandAssessment:
        official = _official_brand(url.hostname, url.registrable_domain, self._catalog)
        if official is not None:
            return BrandAssessment(
                detected=True,
                official_domain=True,
                domain_mismatch=False,
                risk_score=0.0,
                brands=(BrandMatch(official.brand_id, official.aliases[0], LOCATION_REGISTRABLE, False),),
            )

        labels = [label for label in url.hostname.split(".") if label]
        decoded_labels = [idna_decode(label) for label in labels]
        registrable_label = url.registrable_domain.split(".")[0] if url.registrable_domain else ""
        text_tokens = label_tokens(url.path + " " + url.query)
        label_tokens_cache = [label_tokens(decoded) | label_tokens(raw) for raw, decoded in zip(labels, decoded_labels)]
        label_confusable = [decoded != raw or looks_confusable(raw) for raw, decoded in zip(labels, decoded_labels)]
        label_is_registrable = [raw == registrable_label for raw in labels]

        matches: list[BrandMatch] = []
        risk_score = 0.0
        hostname_match = False

        for entry in self._catalog:
            variants = self._variants[entry.brand_id]
            if not variants:
                continue
            for index, tokens in enumerate(label_tokens_cache):
                alias = _label_match(tokens, variants)
                if alias is None:
                    continue
                confusable = label_confusable[index]
                is_registrable = label_is_registrable[index]
                base = _SCORE_REGISTRABLE if is_registrable else _SCORE_SUBDOMAIN
                score = min(1.0, base + (_CONFUSABLE_BONUS if confusable else 0.0))
                location = LOCATION_REGISTRABLE if is_registrable else LOCATION_SUBDOMAIN
                matches.append(BrandMatch(entry.brand_id, alias, location, confusable))
                risk_score = max(risk_score, score)
                hostname_match = True
                break
            else:
                alias = _label_match(text_tokens, variants)
                if alias is not None:
                    matches.append(BrandMatch(entry.brand_id, alias, LOCATION_PATH, False))
                    risk_score = max(risk_score, _SCORE_PATH)

        return BrandAssessment(
            detected=bool(matches),
            official_domain=False,
            domain_mismatch=hostname_match,
            risk_score=risk_score,
            brands=tuple(matches),
        )


def brand_features(assessment: BrandAssessment) -> dict[str, float]:
    return assessment.to_features()


def brand_availability(assessment: BrandAssessment) -> dict[str, bool]:
    return assessment.availability()


def skeleton_of(value: str) -> str:
    return skeleton(value)
