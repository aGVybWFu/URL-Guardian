from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter

import pandas as pd

from src.data.normalizer import NormalizedURL, normalize_url
from .schema import FEATURE_NAMES

KEYWORDS = (
    "login", "signin", "verify", "verification", "secure", "account", "password",
    "update", "payment", "wallet", "bank", "confirm", "auth", "oauth",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def _ip_flags(hostname: str) -> tuple[int, int, int]:
    try:
        address = ipaddress.ip_address(hostname)
        return 1, int(address.version == 4), int(address.version == 6)
    except ValueError:
        return 0, 0, 0


def extract_features(value: str | NormalizedURL) -> dict[str, int | float]:
    parsed = value if isinstance(value, NormalizedURL) else normalize_url(value)
    url = parsed.normalized_url
    lower = url.lower()
    length = len(url)
    digit_count = sum(char.isdigit() for char in url)
    letter_count = sum(char.isalpha() for char in url)
    special_count = sum(not char.isalnum() for char in url)
    has_ip, has_ipv4, has_ipv6 = _ip_flags(parsed.hostname)
    non_default_port = parsed.port is not None and not (
        (parsed.scheme == "http" and parsed.port == 80) or (parsed.scheme == "https" and parsed.port == 443)
    )
    features: dict[str, int | float] = {
        "url_length": length,
        "hostname_length": len(parsed.hostname),
        "registrable_domain_length": len(parsed.registrable_domain),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "subdomain_count": len([part for part in parsed.subdomain.split(".") if part]),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "digit_count": digit_count,
        "letter_count": letter_count,
        "special_character_count": special_count,
        "percent_encoded_count": len(re.findall(r"%[0-9A-F]{2}", url)),
        "parameter_count": 0 if not parsed.query else len(parsed.query.split("&")),
        "is_https": int(parsed.scheme == "https"),
        "is_http": int(parsed.scheme == "http"),
        "has_ip_address": has_ip,
        "has_ipv4": has_ipv4,
        "has_ipv6": has_ipv6,
        "has_punycode": int(any(label.startswith("xn--") for label in parsed.hostname.split("."))),
        "has_at_symbol": int("@" in url),
        "has_non_default_port": int(non_default_port),
        "has_fragment": int(bool(parsed.fragment)),
        "url_entropy": shannon_entropy(url),
        "hostname_entropy": shannon_entropy(parsed.hostname),
        "digit_ratio": digit_count / length,
        "special_character_ratio": special_count / length,
        "hostname_to_url_length_ratio": len(parsed.hostname) / length,
    }
    features.update({f"contains_{keyword}": int(keyword in lower) for keyword in KEYWORDS})
    return {name: features[name] for name in FEATURE_NAMES}


def extract_feature_frame(urls: pd.Series | list[str]) -> pd.DataFrame:
    return pd.DataFrame([extract_features(url) for url in urls], columns=FEATURE_NAMES)

