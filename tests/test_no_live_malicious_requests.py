from pathlib import Path
import urllib.error

import pytest

from src.data.official_downloader import (
    ALLOWED_OFFICIAL_HOSTS,
    fetch_official_bytes,
    redacted_official_url,
    validate_official_url,
)


def test_only_allowlisted_official_hosts_can_be_requested():
    validate_official_url("https://tranco-list.eu/top-1m.csv.zip")
    validate_official_url("https://index.commoncrawl.org/collinfo.json")
    validate_official_url("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")
    validate_official_url("https://hole.cert.pl/domains/v2/domains.json")
    validate_official_url("https://urlhaus-api.abuse.ch/v2/files/exports/test-value/recent.csv")
    with pytest.raises(ValueError):
        validate_official_url("https://malicious.example.test/payload")
    with pytest.raises(ValueError):
        validate_official_url("http://urlhaus-api.abuse.ch/v2/files/exports/test-value/recent.csv")
    with pytest.raises(ValueError):
        validate_official_url("https://urlhaus-api.abuse.ch/v2/files/exports/test-value/other.csv")


def test_network_apis_are_confined_to_official_downloader():
    root = Path(__file__).resolve().parents[1]
    forbidden = ("requests.get(", "requests.post(", "socket.connect(", "getaddrinfo(", "selenium", "playwright")
    for path in [*root.joinpath("src").rglob("*.py"), *root.joinpath("scripts").rglob("*.py")]:
        text = path.read_text(encoding="utf-8").lower()
        assert not any(token in text for token in forbidden), path
        if "urlopen(" in text:
            assert path.name == "official_downloader.py"
    assert ALLOWED_OFFICIAL_HOSTS == {
        "tranco-list.eu", "data.phishtank.com", "urlhaus-api.abuse.ch", "index.commoncrawl.org",
        "raw.githubusercontent.com", "hole.cert.pl", "threatfox-api.abuse.ch", "phish.co.za"
    }


def test_phishing_database_endpoints_are_path_restricted():
    validate_official_url("https://phish.co.za/latest/phishing-domains-ACTIVE.txt")
    validate_official_url(
        "https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/"
        "phishing-domains-ACTIVE.txt.sha256"
    )
    with pytest.raises(ValueError):
        validate_official_url("https://phish.co.za/latest/ALL-phishing-links.tar.gz")
    with pytest.raises(ValueError):
        validate_official_url("https://phish.co.za/other/phishing-domains-ACTIVE.txt")
    with pytest.raises(ValueError):
        validate_official_url(
            "https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/other.sha256"
        )


def test_urlhaus_export_variants_are_path_restricted():
    validate_official_url("https://urlhaus-api.abuse.ch/v2/files/exports/test-value/full.csv")
    validate_official_url("https://urlhaus-api.abuse.ch/v2/files/exports/test-value/active.csv")
    with pytest.raises(ValueError):
        validate_official_url("https://urlhaus-api.abuse.ch/v2/files/exports/test-value/urls.txt")
    with pytest.raises(ValueError):
        validate_official_url("https://urlhaus-api.abuse.ch/v2/files/other/test-value/recent.csv")


def test_threatfox_api_is_restricted_to_the_documented_path():
    validate_official_url("https://threatfox-api.abuse.ch/api/v1/")
    with pytest.raises(ValueError):
        validate_official_url("https://threatfox-api.abuse.ch/api/v1/anything-else")
    with pytest.raises(ValueError):
        validate_official_url("https://threatfox-api.abuse.ch/v2/files/exports/test-value/full.csv.zip")


def test_threatfox_credentials_never_appear_in_a_url():
    from src.data import official_downloader

    source = Path(official_downloader.__file__).read_text(encoding="utf-8")
    assert "THREATFOX_API_URL = \"https://threatfox-api.abuse.ch/api/v1/\"" in source
    assert "{key}" not in source.split("THREATFOX_API_URL")[1].split("\n")[0]


def test_urlhaus_errors_and_metadata_url_are_redacted(monkeypatch):
    secret = "test-secret-not-a-real-key"
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{secret}/recent.csv"

    def fail(*args, **kwargs):
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(RuntimeError) as captured:
        fetch_official_bytes(url, source="urlhaus")
    assert str(captured.value) == "URLhaus authentication failed"
    assert secret not in str(captured.value)
    redacted = redacted_official_url("urlhaus", url)
    assert redacted.endswith("/[REDACTED]/recent.csv")
    assert secret not in redacted
