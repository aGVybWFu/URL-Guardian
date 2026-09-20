import pytest

from src.security.schemes import SchemeOutcome, classify_scheme, is_supported_scheme


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com/", SchemeOutcome.HTTPS),
        ("HTTPS://EXAMPLE.COM/", SchemeOutcome.HTTPS),
        ("http://example.com/", SchemeOutcome.HTTP),
        ("example.com/path", SchemeOutcome.IMPLIED_HTTPS),
        ("javascript:alert(1)", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("file:///etc/passwd", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("content://media/external/images/1", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("intent://scan/#Intent;scheme=zxing;end", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("data:text/html,<script>alert(1)</script>", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("ftp://example.com/file", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("ws://example.com/socket", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("chrome://settings", SchemeOutcome.UNSUPPORTED_SCHEME),
        ("", SchemeOutcome.MALFORMED),
        ("   ", SchemeOutcome.MALFORMED),
    ],
)
def test_classify_scheme(value: str, expected: SchemeOutcome) -> None:
    outcome, _ = classify_scheme(value)
    assert outcome is expected


def test_supported_scheme_helper() -> None:
    assert is_supported_scheme("https://example.com/")
    assert is_supported_scheme("example.com")
    assert not is_supported_scheme("javascript:alert(1)")
    assert not is_supported_scheme("content://x")
    assert not is_supported_scheme("")
