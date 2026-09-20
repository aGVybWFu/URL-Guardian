"""Threat Intelligence contract tests.

The central invariants: UNKNOWN is never SAFE, and UNAVAILABLE/ERROR is never
collapsed into UNKNOWN.
"""

import pytest

from src.threat_intel import (
    ProviderName,
    ThreatIntelligenceService,
    ThreatStatus,
    ThreatFoxProvider,
    UrlHausProvider,
)
from src.threat_intel.contract import (
    SAFE_STATUSES,
    ConfidenceType,
    ThreatIntelligenceResult,
    ThreatType,
    merge,
    provider_error,
    unavailable,
)
from src.threat_intel.providers import SnapshotIndexProvider


def test_unknown_is_never_treated_as_safe():
    result = ThreatIntelligenceResult(status=ThreatStatus.UNKNOWN)
    assert result.is_unknown() is True
    assert result.is_known_malicious() is False
    assert result.is_safe() is False
    assert result.to_dict()["safeStatusAvailable"] is False


def test_there_is_no_safe_status_at_all():
    assert SAFE_STATUSES == frozenset()
    assert "SAFE" not in {status.value for status in ThreatStatus}


def test_error_is_distinct_from_unknown():
    error = provider_error(ProviderName.URLHAUS, "index unreadable")
    assert error.status is ThreatStatus.ERROR
    assert error.is_provider_problem() is True
    assert error.is_unknown() is False
    assert error.status is not ThreatStatus.UNKNOWN


def test_unavailable_is_distinct_from_unknown():
    result = unavailable(ProviderName.THREATFOX, "snapshot missing")
    assert result.status is ThreatStatus.UNAVAILABLE
    assert result.is_provider_problem() is True
    assert result.is_unknown() is False


def test_merge_prefers_a_confirmed_hit_over_a_miss():
    hit = ThreatIntelligenceResult(
        status=ThreatStatus.KNOWN_MALICIOUS,
        threat_type=ThreatType.MALWARE,
        providers=(ProviderName.URLHAUS,),
        confidence_type=ConfidenceType.EXACT_MATCH,
        matched_indicator="192.0.2.1",
    )
    merged = merge([ThreatIntelligenceResult(status=ThreatStatus.UNKNOWN), hit])
    assert merged.status is ThreatStatus.KNOWN_MALICIOUS
    assert merged.providers == (ProviderName.URLHAUS,)


def test_merge_surfaces_a_provider_problem_before_a_plain_miss():
    merged = merge(
        [
            ThreatIntelligenceResult(status=ThreatStatus.UNKNOWN),
            unavailable(ProviderName.THREATFOX, "snapshot missing"),
        ]
    )
    assert merged.status is ThreatStatus.UNAVAILABLE
    assert merged.is_unknown() is False


def test_merge_of_only_misses_is_unknown():
    merged = merge([ThreatIntelligenceResult(status=ThreatStatus.UNKNOWN)])
    assert merged.status is ThreatStatus.UNKNOWN
    assert merged.is_safe() is False


def test_merge_combines_providers_for_multiple_hits():
    first = ThreatIntelligenceResult(
        status=ThreatStatus.KNOWN_MALICIOUS,
        threat_type=ThreatType.MALWARE,
        providers=(ProviderName.URLHAUS,),
        confidence_type=ConfidenceType.EXACT_MATCH,
        matched_indicator="192.0.2.1",
    )
    second = ThreatIntelligenceResult(
        status=ThreatStatus.KNOWN_MALICIOUS,
        threat_type=ThreatType.MALWARE,
        providers=(ProviderName.THREATFOX,),
        confidence_type=ConfidenceType.DOMAIN_MATCH,
        matched_indicator="evil.example",
    )
    merged = merge([first, second])
    assert set(merged.providers) == {ProviderName.URLHAUS, ProviderName.THREATFOX}
    assert merged.confidence_type is ConfidenceType.EXACT_MATCH


def test_missing_snapshot_yields_unavailable_not_unknown():
    provider = UrlHausProvider(None, detail="snapshot directory is missing")
    assert provider.is_available() is False
    result = provider.lookup("192.0.2.1")
    assert result.status is ThreatStatus.UNAVAILABLE
    assert result.is_unknown() is False


def test_index_provider_returns_known_malicious_for_a_listed_indicator():
    provider = SnapshotIndexProvider([("192.0.2.1", "2026-09-20")])
    result = provider.lookup("192.0.2.1")
    assert result.status is ThreatStatus.KNOWN_MALICIOUS
    assert result.threat_type is ThreatType.MALWARE
    assert result.confidence_type is ConfidenceType.EXACT_MATCH
    assert result.source_timestamp == "2026-09-20"


def test_index_provider_domain_lookup_matches_hostname_then_registrable_domain():
    provider = SnapshotIndexProvider([("evil.example.com", None)])
    by_host = provider.lookup_url("evil.example.com", "example.com")
    assert by_host.status is ThreatStatus.KNOWN_MALICIOUS
    assert by_host.confidence_type is ConfidenceType.DOMAIN_MATCH
    miss = provider.lookup_url("good.example.com", "example.com")
    assert miss.status is ThreatStatus.UNKNOWN


def test_empty_indicator_is_an_error_not_a_miss():
    provider = SnapshotIndexProvider([("evil.example.com", None)])
    result = provider.lookup("   ")
    assert result.status is ThreatStatus.ERROR


def test_service_reports_provider_availability_separately():
    service = ThreatIntelligenceService(
        [UrlHausProvider([("192.0.2.1", None)]), ThreatFoxProvider(None, detail="missing")]
    )
    status = service.provider_status()
    assert status == {"URLHAUS": "AVAILABLE", "THREATFOX": "UNAVAILABLE"}


def test_service_lookup_returns_unknown_for_an_unlisted_domain():
    service = ThreatIntelligenceService([UrlHausProvider([("192.0.2.1", None)])])
    result = service.lookup("definitely-not-listed.example")
    assert result.status is ThreatStatus.UNKNOWN
    assert result.is_safe() is False


def test_official_service_indexes_are_available_and_non_trivial():
    from pathlib import Path

    raw_root = Path(__file__).resolve().parents[1] / "data" / "raw"
    if not raw_root.exists():
        pytest.skip("raw snapshots are not present in this environment")
    service = ThreatIntelligenceService.from_raw_root(raw_root)
    status = service.provider_status()
    if status.get("URLHAUS") != "AVAILABLE":
        pytest.skip("URLhaus snapshot is not present")
    assert all(provider.index_size() > 0 for provider in service.providers if provider.is_available())


def test_results_never_contain_credentials():
    result = ThreatIntelligenceResult(
        status=ThreatStatus.KNOWN_MALICIOUS,
        threat_type=ThreatType.MALWARE,
        providers=(ProviderName.URLHAUS,),
        confidence_type=ConfidenceType.EXACT_MATCH,
        matched_indicator="192.0.2.1",
    )
    payload = result.to_dict()
    serialized = str(payload).lower()
    for token in ("auth-key", "auth_key", "token", "secret", "password"):
        assert token not in serialized
