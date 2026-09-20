from __future__ import annotations

import os
from pathlib import Path

ALLOWED_SECRET_NAMES = {"PHISHTANK_APP_KEY", "URLHAUS_AUTH_KEY", "THREATFOX_AUTH_KEY"}

# abuse.ch issues one Auth-Key per account through its authentication portal, so the
# ThreatFox key may legitimately be the same value as the URLhaus key. ThreatFox is
# preferred as an explicit variable, with the shared abuse.ch key as a documented
# fallback. The value is never printed, logged or written to metadata.
THREATFOX_KEY_NAMES = ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY")


def threatfox_auth_key() -> tuple[str, str | None]:
    """Return the ThreatFox Auth-Key and the variable name it came from."""

    for name in THREATFOX_KEY_NAMES:
        value = os.environ.get(name, "").strip()
        if value:
            return value, name
    return "", None


def load_secret_environment(path: str | Path) -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for line_number, raw_line in enumerate(env_path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid .env entry at line {line_number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if name not in ALLOWED_SECRET_NAMES:
            raise ValueError(f"Unsupported secret name in .env: {name}")
        os.environ.setdefault(name, value.strip().strip('"').strip("'"))
