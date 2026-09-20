from src.data.normalizer import normalize_url
from src.intel.shortener_engine import ShortenerDetectionEngine

ENGINE = ShortenerDetectionEngine()


def test_known_shortener_is_detected() -> None:
    result = ENGINE.assess(normalize_url("https://bit.ly/abc123"))
    assert result.detected
    assert result.domain == "bit.ly"
    assert result.to_features()["shortener_detected"] == 1.0


def test_shortener_subdomain_is_detected() -> None:
    assert ENGINE.assess(normalize_url("https://go.bit.ly/xyz")).detected


def test_regular_domain_is_not_a_shortener() -> None:
    assert not ENGINE.assess(normalize_url("https://example.com/path")).detected


def test_official_platform_shorteners_are_excluded() -> None:
    for raw in ("https://youtu.be/abc", "https://t.me/channel", "https://discord.gg/invite"):
        assert not ENGINE.assess(normalize_url(raw)).detected


def test_lookalike_shortener_domain_is_not_detected() -> None:
    assert not ENGINE.assess(normalize_url("https://bit.ly.example.com/abc")).detected
