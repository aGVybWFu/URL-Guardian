from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = 1

_FEATURES = [
    ("url_length", "Total normalized URL length", "integer"),
    ("hostname_length", "ASCII hostname length", "integer"),
    ("registrable_domain_length", "Public-Suffix-aware registrable domain length", "integer"),
    ("path_length", "Path length without query or fragment", "integer"),
    ("query_length", "Query string length", "integer"),
    ("subdomain_count", "Number of subdomain labels", "integer"),
    ("dot_count", "Count of dots in the URL", "integer"),
    ("hyphen_count", "Count of hyphens in the URL", "integer"),
    ("underscore_count", "Count of underscores in the URL", "integer"),
    ("slash_count", "Count of slashes in the URL", "integer"),
    ("digit_count", "Count of decimal digits", "integer"),
    ("letter_count", "Count of Unicode alphabetic characters", "integer"),
    ("special_character_count", "Count of non-alphanumeric characters", "integer"),
    ("percent_encoded_count", "Count of percent-encoded octets", "integer"),
    ("parameter_count", "Count of ampersand-separated query parameters", "integer"),
    ("is_https", "URL uses HTTPS", "boolean"),
    ("is_http", "URL uses HTTP", "boolean"),
    ("has_ip_address", "Hostname is an IPv4 or IPv6 literal", "boolean"),
    ("has_ipv4", "Hostname is an IPv4 literal", "boolean"),
    ("has_ipv6", "Hostname is an IPv6 literal", "boolean"),
    ("has_punycode", "Hostname contains an xn-- label", "boolean"),
    ("has_at_symbol", "URL contains an at sign", "boolean"),
    ("has_non_default_port", "URL specifies a non-default port", "boolean"),
    ("has_fragment", "URL contains a fragment", "boolean"),
    ("contains_login", "URL contains the token login", "boolean"),
    ("contains_signin", "URL contains the token signin", "boolean"),
    ("contains_verify", "URL contains the token verify", "boolean"),
    ("contains_verification", "URL contains the token verification", "boolean"),
    ("contains_secure", "URL contains the token secure", "boolean"),
    ("contains_account", "URL contains the token account", "boolean"),
    ("contains_password", "URL contains the token password", "boolean"),
    ("contains_update", "URL contains the token update", "boolean"),
    ("contains_payment", "URL contains the token payment", "boolean"),
    ("contains_wallet", "URL contains the token wallet", "boolean"),
    ("contains_bank", "URL contains the token bank", "boolean"),
    ("contains_confirm", "URL contains the token confirm", "boolean"),
    ("contains_auth", "URL contains the token auth", "boolean"),
    ("contains_oauth", "URL contains the token oauth", "boolean"),
    ("url_entropy", "Shannon entropy of the normalized URL", "float"),
    ("hostname_entropy", "Shannon entropy of the hostname", "float"),
    ("digit_ratio", "Digit count divided by URL length", "float"),
    ("special_character_ratio", "Special-character count divided by URL length", "float"),
    ("hostname_to_url_length_ratio", "Hostname length divided by URL length", "float"),
]

FEATURE_NAMES = [item[0] for item in _FEATURES]


def feature_schema() -> dict[str, object]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "features": [
            {"name": name, "description": description, "type": feature_type}
            for name, description, feature_type in _FEATURES
        ],
    }


def write_feature_schema(path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(feature_schema(), ensure_ascii=False, indent=2), encoding="utf-8")

