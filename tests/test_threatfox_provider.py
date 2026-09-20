"""ThreatFox provider tests: parsing, threat-type semantics and secret redaction."""

import json

import pytest

from src.data.official_downloader import OfficialDownloadError, validate_official_url
from src.data.sources import ThreatFoxProvider, parse_threatfox
from src.utils.env import ALLOWED_SECRET_NAMES, threatfox_auth_key

PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "id": "1",
            "ioc": "payload.example.com",
            "ioc_type": "domain",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Domain name that delivers a malware payload",
            "malware": "win.loader",
            "malware_printable": "Loader",
            "confidence_level": 75,
            "first_seen": "2026-09-19 00:00:00 UTC",
            "tags": ["exe"],
        },
        {
            "id": "2",
            "ioc": "c2.example.net",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "malware": "win.bot",
            "confidence_level": 50,
            "tags": None,
        },
        {
            "id": "3",
            "ioc": "http://payload.example.org/a",
            "ioc_type": "url",
            "threat_type": "payload_delivery",
            "malware": "win.loader",
            "confidence_level": 100,
        },
        {
            "id": "4",
            "ioc": "203.0.113.10:443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "win.bot",
            "confidence_level": 100,
        },
    ],
}


def test_threatfox_parser_keeps_only_domain_payload_delivery_by_default():
    frame = parse_threatfox(PAYLOAD, "2026-09-20")
    assert len(frame) == 1
    assert frame.loc[0, "url"] == "https://payload.example.com/"
    assert frame.loc[0, "label"] == "MALWARE"
    assert frame.loc[0, "source"] == "threatfox"
    assert frame.loc[0, "threat_type"] == "payload_delivery"
    assert frame.loc[0, "label_confidence"] == "confirmed_ioc"


def test_threatfox_parser_excludes_botnet_cc_unless_explicitly_broadened():
    default = parse_threatfox(PAYLOAD, "2026-09-20")
    assert "c2.example.net" not in set(default["url"])
    broadened = parse_threatfox(PAYLOAD, "2026-09-20", ("payload_delivery", "botnet_cc"))
    assert "https://c2.example.net/" in set(broadened["url"])


def test_threatfox_provider_defaults_match_the_documented_semantics():
    provider = ThreatFoxProvider()
    assert provider.default_threat_types == ("payload_delivery",)
    frame = provider.parse(PAYLOAD, "2026-09-20")
    assert set(frame["threat_type"]) == {"payload_delivery"}


def test_threatfox_parser_rejects_a_payload_without_usable_rows():
    with pytest.raises(ValueError, match="no usable domain IOCs"):
        parse_threatfox({"query_status": "ok", "data": []}, "2026-09-20")


def test_threatfox_parser_accepts_a_local_json_file(tmp_path):
    path = tmp_path / "threatfox.json"
    path.write_text(json.dumps(PAYLOAD), encoding="utf-8")
    frame = parse_threatfox(path, "2026-09-20")
    assert len(frame) == 1


def test_threatfox_api_host_is_allowlisted_and_https_only():
    validate_official_url("https://threatfox-api.abuse.ch/api/v1/")
    with pytest.raises(ValueError):
        validate_official_url("http://threatfox-api.abuse.ch/api/v1/")
    with pytest.raises(ValueError):
        validate_official_url("https://threatfox-api.abuse.ch/api/v2/")


def test_threatfox_key_is_a_recognised_secret_name():
    assert "THREATFOX_AUTH_KEY" in ALLOWED_SECRET_NAMES


def test_threatfox_auth_prefers_its_own_variable_and_falls_back_to_the_abuse_ch_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    assert threatfox_auth_key() == ("", None)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "shared-abuse-ch-key")
    assert threatfox_auth_key() == ("shared-abuse-ch-key", "URLHAUS_AUTH_KEY")
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "dedicated-threatfox-key")
    assert threatfox_auth_key() == ("dedicated-threatfox-key", "THREATFOX_AUTH_KEY")


def test_threatfox_errors_never_leak_the_key(monkeypatch):
    secret = "super-secret-threatfox-key"
    from src.data import official_downloader

    def fail(*args, **kwargs):
        raise OfficialDownloadError("ThreatFox authentication failed", status=403)

    monkeypatch.setattr(official_downloader, "post_official_json", fail)
    with pytest.raises(OfficialDownloadError) as captured:
        official_downloader.fetch_threatfox_iocs(days=7, auth_key=secret)
    assert secret not in str(captured.value)
    assert "authentication" in str(captured.value).lower()


def test_threatfox_provider_never_puts_the_key_into_a_url():
    source = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "src"
        / "data"
        / "official_downloader.py"
    ).read_text(encoding="utf-8")
    assert 'auth_header=("Auth-Key", auth_key)' in source
    threatfox_urls = [
        line for line in source.splitlines() if "threatfox-api.abuse.ch" in line and "http" in line
    ]
    assert threatfox_urls
    for line in threatfox_urls:
        assert "{key}" not in line
        assert "AUTH" not in line.upper() or "Auth-Key" in line
