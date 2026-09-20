import pytest

from src.data.normalizer import URLNormalizationError, normalize_url


def test_normalizes_scheme_host_trailing_dot_and_fragment():
    parsed = normalize_url("HTTPS://GOOGLE.COM./login#abc")
    assert parsed.normalized_url == "https://google.com/login#abc"
    assert parsed.registrable_domain == "google.com"


def test_ipv4_ipv6_idn_and_percent_encoding():
    assert normalize_url("http://192.0.2.10/a").registrable_domain == "192.0.2.10"
    assert normalize_url("http://[2001:db8::1]:8080/a").normalized_url == "http://[2001:db8::1]:8080/a"
    assert normalize_url("https://例え.テスト/").hostname.startswith("xn--")
    assert normalize_url("https://example.com/%2f?q=%aa").normalized_url.endswith("/%2F?q=%AA")


@pytest.mark.parametrize("value", ["", "ftp://example.com/a", "https://example.com/%GG", "http://"])
def test_rejects_invalid_urls(value):
    with pytest.raises(URLNormalizationError):
        normalize_url(value)


def test_long_url_boundary():
    normalize_url("https://example.com/" + "a" * 1000)
    with pytest.raises(URLNormalizationError):
        normalize_url("https://example.com/" + "a" * 9000)

