from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import asdict, dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import tldextract

from src.security.schemes import SchemeOutcome, classify_scheme

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")


class URLNormalizationError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedURL:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    subdomain: str
    domain: str
    suffix: str
    registrable_domain: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _normalize_percent(value: str) -> str:
    if _BAD_PERCENT.search(value):
        raise URLNormalizationError("Malformed percent encoding")
    return _PERCENT.sub(lambda match: match.group(0).upper(), value)


def _domain_parts(hostname: str) -> tuple[str, str, str, str]:
    try:
        ipaddress.ip_address(hostname)
        return "", hostname, "", hostname
    except ValueError:
        extracted = _EXTRACT(hostname)
        registrable = extracted.top_domain_under_public_suffix or hostname
        return extracted.subdomain, extracted.domain, extracted.suffix, registrable


def normalize_url(value: object, max_length: int = 8192) -> NormalizedURL:
    if value is None:
        raise URLNormalizationError("URL is empty")
    original = str(value)
    raw = unicodedata.normalize("NFC", original).strip()
    if not raw or len(raw) > max_length:
        raise URLNormalizationError("URL is empty or too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise URLNormalizationError("URL contains control characters")
    scheme_outcome, _ = classify_scheme(raw)
    if scheme_outcome is SchemeOutcome.UNSUPPORTED_SCHEME:
        raise URLNormalizationError("Only HTTP and HTTPS URLs are accepted")
    candidate = raw if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw) else f"https://{raw}"
    try:
        parsed: SplitResult = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise URLNormalizationError("Only HTTP and HTTPS URLs are accepted")
        hostname = parsed.hostname
        if not hostname or any(char.isspace() for char in hostname):
            raise URLNormalizationError("Hostname is missing or invalid")
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not hostname:
            raise URLNormalizationError("Hostname is empty")
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise URLNormalizationError("URL cannot be parsed") from error

    try:
        ip_value = ipaddress.ip_address(hostname)
        host_display = f"[{hostname}]" if ip_value.version == 6 else hostname
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", hostname) or ".." in hostname:
            raise URLNormalizationError("Hostname is invalid")
        host_display = hostname

    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    port_text = "" if port is None or default_port else f":{port}"
    path = _normalize_percent(parsed.path)
    query = _normalize_percent(parsed.query)
    fragment = _normalize_percent(parsed.fragment)
    normalized = urlunsplit((scheme, f"{userinfo}{host_display}{port_text}", path, query, fragment))
    subdomain, domain, suffix, registrable = _domain_parts(hostname)
    return NormalizedURL(
        original_url=original,
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registrable_domain=registrable,
    )

