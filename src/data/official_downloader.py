from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

import certifi

USER_AGENT = "URL-Guardian-Research/0.6 (static dataset builder; educational research)"
ALLOWED_OFFICIAL_HOSTS = {
    "tranco-list.eu",
    "data.phishtank.com",
    "urlhaus-api.abuse.ch",
    "index.commoncrawl.org",
    "raw.githubusercontent.com",
    "hole.cert.pl",
    "threatfox-api.abuse.ch",
    "phish.co.za",
}

URLHAUS_EXPORT_PATH = re.compile(r"^/v2/files/exports/[^/]+/(recent|full|active)\.csv$")
THREATFOX_API_PATH = "/api/v1/"
PHISHING_DATABASE_DOMAIN_PATH = "/latest/phishing-domains-ACTIVE.txt"
PHISHING_DATABASE_CHECKSUM_PATH = (
    "/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256"
)
COMMONCRAWL_INDEX_PATH = re.compile(r"^/CC-MAIN-\d{4}-\d{2}-index$")
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_API_RESPONSE_BYTES = 64 * 1024 * 1024
TLS_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class OfficialDownloadError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        reason_type: str | None = None,
        verify_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.reason_type = reason_type
        self.verify_code = verify_code


def validate_official_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_OFFICIAL_HOSTS:
        raise ValueError(f"Network access is restricted to official dataset endpoints: {parsed.hostname!r}")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Official dataset endpoints cannot contain userinfo or a non-default port")
    allowed_path = {
        "tranco-list.eu": parsed.path in {"/top-1m.csv.zip", "/top-1m-id"},
        "data.phishtank.com": parsed.path == "/data/online-valid.csv.bz2",
        "urlhaus-api.abuse.ch": bool(URLHAUS_EXPORT_PATH.fullmatch(parsed.path)),
        "index.commoncrawl.org": parsed.path == "/collinfo.json"
        or bool(COMMONCRAWL_INDEX_PATH.fullmatch(parsed.path)),
        "raw.githubusercontent.com": parsed.path
        in {
            "/openphish/public_feed/refs/heads/main/feed.txt",
            PHISHING_DATABASE_CHECKSUM_PATH,
        },
        "hole.cert.pl": parsed.path == "/domains/v2/domains.json",
        "threatfox-api.abuse.ch": parsed.path == THREATFOX_API_PATH,
        "phish.co.za": parsed.path == PHISHING_DATABASE_DOMAIN_PATH,
    }[parsed.hostname]
    if not allowed_path:
        raise ValueError("Network access is restricted to an approved official dataset path")


def fetch_official_bytes(url: str, timeout: int = 120, source: str | None = None) -> bytes:
    validate_official_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(  # nosec: exact official endpoint with verified TLS
            request, timeout=timeout, context=TLS_CONTEXT
        ) as response:
            final_url = response.geturl()
            validate_official_url(final_url)
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("Official dataset response exceeds the download size limit")
            payload = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(payload) > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("Official dataset response exceeds the download size limit")
            return payload
    except urllib.error.HTTPError as error:
        if source == "urlhaus" and error.code in {401, 403}:
            raise OfficialDownloadError("URLhaus authentication failed", status=error.code) from None
        if source == "urlhaus":
            raise OfficialDownloadError("URLhaus download failed", status=error.code) from None
        raise OfficialDownloadError(
            f"Official {source or 'dataset'} download failed with HTTP {error.code}", status=error.code
        ) from None
    except urllib.error.URLError as error:
        reason_type = type(error.reason).__name__
        verify_code = getattr(error.reason, "verify_code", None)
        if source == "urlhaus":
            raise OfficialDownloadError(
                "URLhaus download failed", reason_type=reason_type, verify_code=verify_code
            ) from None
        raise OfficialDownloadError(
            f"Official {source or 'dataset'} download failed",
            reason_type=reason_type,
            verify_code=verify_code,
        ) from None


def post_official_json(
    url: str,
    payload: dict[str, object],
    *,
    auth_header: tuple[str, str] | None = None,
    timeout: int = 120,
    source: str | None = None,
) -> dict[str, object]:
    """POST JSON to an approved official API using header authentication.

    This is the only non-GET egress in the project. It exists so that providers
    whose documentation defines an `Auth-Key` request header (ThreatFox) never
    need the credential-in-path exception. The credential is placed in a request
    header only and is never included in any logged or persisted URL.
    """

    validate_official_url(url)
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if auth_header is not None:
        name, value = auth_header
        if not value:
            raise OfficialDownloadError(f"{name} is required for this official API")
        headers[name] = value
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(  # nosec: exact official API endpoint with verified TLS
            request, timeout=timeout, context=TLS_CONTEXT
        ) as response:
            final_url = response.geturl()
            validate_official_url(final_url)
            raw = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(raw) > MAX_API_RESPONSE_BYTES:
                raise OfficialDownloadError("Official API response exceeds the size limit")
    except urllib.error.HTTPError as error:
        if source == "threatfox" and error.code in {401, 403}:
            raise OfficialDownloadError("ThreatFox authentication failed", status=error.code) from None
        if source == "threatfox":
            raise OfficialDownloadError("ThreatFox request failed", status=error.code) from None
        raise OfficialDownloadError(
            f"Official {source or 'api'} request failed with HTTP {error.code}", status=error.code
        ) from None
    except urllib.error.URLError as error:
        reason_type = type(error.reason).__name__
        if source == "threatfox":
            raise OfficialDownloadError("ThreatFox request failed", reason_type=reason_type) from None
        raise OfficialDownloadError(
            f"Official {source or 'api'} request failed", reason_type=reason_type
        ) from None
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise OfficialDownloadError("Official API returned an unexpected payload shape")
    return parsed


def official_source_url(source: str) -> str:
    if source == "tranco":
        return "https://tranco-list.eu/top-1m.csv.zip"
    if source == "phishtank":
        return "https://data.phishtank.com/data/online-valid.csv.bz2"
    if source == "urlhaus":
        return urlhaus_export_url("recent")
    if source == "openphish":
        return "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    if source == "cert_polska":
        return "https://hole.cert.pl/domains/v2/domains.json"
    if source == "phishing_database":
        return f"https://phish.co.za{PHISHING_DATABASE_DOMAIN_PATH}"
    raise ValueError(f"Unsupported official source: {source}")


PHISHING_DATABASE_CHECKSUM_URL = f"https://raw.githubusercontent.com{PHISHING_DATABASE_CHECKSUM_PATH}"


def fetch_phishing_database_checksum() -> str:
    """Fetch the publisher-provided SHA-256 for the Phishing.Database domain feed."""

    return fetch_official_bytes(PHISHING_DATABASE_CHECKSUM_URL, timeout=60, source="phishing_database").decode(
        "utf-8"
    )


def urlhaus_export_url(variant: str = "recent") -> str:
    """Build the official URLhaus export URL for an approved variant.

    This is the narrow credential-in-path exception: the official URLhaus API
    documentation requires the Auth-Key inside the HTTPS path. The URL is only
    ever used internally and is always redacted before logging or persistence.
    """

    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        raise RuntimeError("URLHAUS_AUTH_KEY is required for the official URLhaus database export")
    if variant not in {"recent", "full", "active"}:
        raise ValueError(f"Unsupported URLhaus export variant: {variant}")
    return f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/{variant}.csv"


def redacted_official_url(source: str, url: str) -> str:
    if source == "urlhaus":
        variant = urlsplit(url).path.rsplit("/", 1)[-1] or "recent.csv"
        return f"https://urlhaus-api.abuse.ch/v2/files/exports/[REDACTED]/{variant}"
    return url


def download_official_source(
    source: str, destination: str | Path, url: str | None = None
) -> tuple[Path, str]:
    target_url = url or official_source_url(source)
    payload = fetch_official_bytes(target_url, source=source)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = sha256(path.read_bytes()).hexdigest()
        incoming = sha256(payload).hexdigest()
        if existing != incoming:
            raise RuntimeError("Immutable snapshot already contains different content for this source")
    else:
        temporary = path.with_suffix(path.suffix + ".part")
        temporary.write_bytes(payload)
        temporary.replace(path)
    return path, redacted_official_url(source, target_url)


def fetch_tranco_list_id() -> str:
    return fetch_official_bytes("https://tranco-list.eu/top-1m-id", timeout=30).decode("utf-8").strip()


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox_iocs(days: int = 7, auth_key: str = "") -> dict[str, object]:
    """Query the official ThreatFox IOC API using header authentication only."""

    if not 1 <= int(days) <= 7:
        raise ValueError("ThreatFox get_iocs accepts days between 1 and 7")
    if not auth_key:
        raise OfficialDownloadError("ThreatFox authentication is required for the official API")
    return post_official_json(
        THREATFOX_API_URL,
        {"query": "get_iocs", "days": int(days)},
        auth_header=("Auth-Key", auth_key),
        source="threatfox",
    )
