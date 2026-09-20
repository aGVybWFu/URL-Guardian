"""URL scheme policy.

URL Guardian accepts exactly `http` and `https`. Everything else (`javascript:`,
`file:`, `content:`, `intent:`, `data:`, `ftp:`, `ws:`, custom schemes) is an
explicit `UNSUPPORTED_SCHEME` outcome and must never reach browser handoff or a
network path. Scheme-less input is treated as `https` by the normalizer, which
is recorded as `IMPLIED_HTTPS`.
"""

from __future__ import annotations

import re
from enum import Enum

SUPPORTED_SCHEMES = ("http", "https")
SCHEME_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"


class SchemeOutcome(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    IMPLIED_HTTPS = "IMPLIED_HTTPS"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    MALFORMED = "MALFORMED"


def classify_scheme(value: object) -> tuple[SchemeOutcome, str | None]:
    """Return the scheme outcome and the detected scheme name, if any."""

    text = str(value).strip()
    if not text:
        return SchemeOutcome.MALFORMED, None
    match = SCHEME_PATTERN.match(text)
    if match is None:
        return SchemeOutcome.IMPLIED_HTTPS, None
    scheme = match.group(1).lower()
    if scheme == "https":
        return SchemeOutcome.HTTPS, scheme
    if scheme == "http":
        return SchemeOutcome.HTTP, scheme
    return SchemeOutcome.UNSUPPORTED_SCHEME, scheme


def is_supported_scheme(value: object) -> bool:
    outcome, _ = classify_scheme(value)
    return outcome in {SchemeOutcome.HTTP, SchemeOutcome.HTTPS, SchemeOutcome.IMPLIED_HTTPS}
