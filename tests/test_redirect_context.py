import pytest

from src.data.normalizer import normalize_url
from src.intel.redirect import (
    FixtureRedirectResolver,
    NoOpRedirectResolver,
    RedirectContext,
    STATUS_NOT_OBSERVED,
    STATUS_OBSERVED,
)


def test_noop_resolver_never_observes_and_reports_unavailable() -> None:
    context = NoOpRedirectResolver().resolve(normalize_url("https://example.com/"))
    assert context.status == STATUS_NOT_OBSERVED
    assert not context.observed
    assert context.to_features() == {}
    assert context.availability() == {"redirect_count": False, "cross_domain_redirect": False}


def test_fixture_resolver_reports_observed_context() -> None:
    url = "https://example.com/"
    resolver = FixtureRedirectResolver(
        {url: RedirectContext(STATUS_OBSERVED, redirect_count=2, cross_domain_redirect=True, final_hostname="evil.example")}
    )
    context = resolver.resolve(normalize_url(url))
    assert context.observed
    assert context.to_features() == {"redirect_count": 2.0, "cross_domain_redirect": 1.0}
    assert context.availability() == {"redirect_count": True, "cross_domain_redirect": True}


def test_unknown_url_is_not_observed() -> None:
    resolver = FixtureRedirectResolver({})
    assert resolver.resolve(normalize_url("https://unknown.example/")).status == STATUS_NOT_OBSERVED


def test_negative_redirect_count_is_rejected() -> None:
    with pytest.raises(ValueError):
        RedirectContext(STATUS_OBSERVED, redirect_count=-1)


def test_unknown_status_is_rejected() -> None:
    with pytest.raises(ValueError):
        RedirectContext("MAYBE")
