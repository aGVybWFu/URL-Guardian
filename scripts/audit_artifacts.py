"""Phase 6 artifact audit: size breakdown, ABI contents, manifest permissions,
secret scan and network-stack scan for APK and AAB artifacts.

Read-only. Never installs anything and never touches a URL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = Path.home() / "ug-build" / "URLGuardianAndroid" / "app" / "outputs"
DEFAULT_REPORT = ROOT / "reports" / "deployment" / "phase6_artifact_audit.json"
ALLOWED_ABIS = {"arm64-v8a", "x86_64"}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("URLHAUS_AUTH_KEY", re.compile(rb"URLHAUS_AUTH_KEY", re.IGNORECASE)),
    ("THREATFOX_AUTH_KEY", re.compile(rb"THREATFOX_AUTH_KEY", re.IGNORECASE)),
    ("authorization: bearer", re.compile(rb"authorization\s*:\s*bearer", re.IGNORECASE)),
    ("auth-key-assignment", re.compile(rb"auth[-_]?key\s*[:=]\s*\S{8,}", re.IGNORECASE)),
    ("private-key-block", re.compile(rb"-----\s*BEGIN (RSA |EC )?PRIVATE KEY", re.IGNORECASE)),
    ("github-token", re.compile(rb"ghp_[A-Za-z0-9]{20,}")),
    ("aws-access-key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("openai-style-key", re.compile(rb"sk-[A-Za-z0-9]{20,}")),
)
NETWORK_MARKERS = (
    "okhttp3/",
    "retrofit2/",
    "com/squareup/okhttp",
    "com/android/volley",
    "io/ktor/",
)
PERMISSION_MARKERS = ("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE")
MAX_SCAN_BYTES = 64 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_bytes(archive: zipfile.ZipFile, name: str, limit: int = MAX_SCAN_BYTES) -> bytes:
    with archive.open(name) as handle:
        return handle.read(limit)


def _categorize(entries: list[dict[str, Any]], is_bundle: bool) -> dict[str, int]:
    prefix = "base/" if is_bundle else ""

    def total(predicate) -> int:
        return sum(entry["size"] for entry in entries if predicate(entry["name"]))

    dex = total(lambda name: re.match(rf"^{prefix}dex/.*\.dex$", name) is not None) if is_bundle else total(
        lambda name: name.startswith("classes") and name.endswith(".dex")
    )
    return {
        "nativeLibs": total(lambda name: re.match(rf"^{prefix}lib/", name) is not None),
        "assets": total(lambda name: re.match(rf"^{prefix}assets/", name) is not None),
        "dex": dex,
        "resources": total(lambda name: re.match(rf"^{prefix}res/", name) is not None),
        "metaInf": total(lambda name: name.startswith("META-INF/")),
    }


def audit_archive(path: Path) -> dict[str, Any]:
    is_bundle = path.suffix == ".aab"
    with zipfile.ZipFile(path) as archive:
        entries = [
            {"name": info.filename, "size": info.file_size, "compressed": info.compress_size}
            for info in archive.infolist() if not info.is_dir()
        ]
        libs = [entry for entry in entries if re.search(r"(^|/)lib/", entry["name"])]
        abis = sorted({
            match.group(1)
            for entry in libs
            if (match := re.search(r"(?:^|/)lib/([^/]+)/", entry["name"])) is not None
        })
        manifest_names = [name for name in archive.namelist() if name.endswith("AndroidManifest.xml")]
        manifest_bytes = _entry_bytes(archive, manifest_names[0]) if manifest_names else b""
        permissions_present = {
            marker: marker.encode("ascii") in manifest_bytes for marker in PERMISSION_MARKERS
        }
        secret_hits: list[dict[str, str]] = []
        network_hits: list[str] = []
        for entry in entries:
            name = entry["name"]
            if not re.search(r"\.(dex|json|txt|xml|properties|js|html)$", name) and not name.endswith(".so"):
                continue
            if entry["size"] > MAX_SCAN_BYTES:
                continue
            try:
                payload = _entry_bytes(archive, name)
            except (KeyError, zipfile.BadZipFile, RuntimeError):
                continue
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(payload):
                    secret_hits.append({"entry": name, "pattern": label})
            if name.endswith(".dex"):
                text = payload
                for marker in NETWORK_MARKERS:
                    if marker.encode("ascii") in text:
                        network_hits.append(f"{name}:{marker}")
        assets = sorted(
            (entry for entry in entries if re.search(r"(^|/)assets/", entry["name"])),
            key=lambda item: -item["size"],
        )
        categories = _categorize(entries, is_bundle)
        checks = {
            "onlyAllowedAbis": set(abis) <= ALLOWED_ABIS,
            "noInternetPermission": not permissions_present["android.permission.INTERNET"],
            "noAccessNetworkStatePermission": not permissions_present["android.permission.ACCESS_NETWORK_STATE"],
            "noSecretPatterns": not secret_hits,
            "noKnownNetworkStack": not network_hits,
        }
        return {
            "artifact": str(path),
            "kind": "aab" if is_bundle else "apk",
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "uncompressedBytes": sum(entry["size"] for entry in entries),
            "categories": categories,
            "abis": abis,
            "nativeLibs": [
                {"name": entry["name"], "size": entry["size"]}
                for entry in sorted(libs, key=lambda item: -item["size"])
            ],
            "assets": [{"name": entry["name"], "size": entry["size"]} for entry in assets],
            "manifestChecked": bool(manifest_names),
            "permissionsPresent": permissions_present,
            "secretHits": secret_hits,
            "networkHits": network_hits,
            "checks": checks,
            "passed": all(checks.values()),
        }


def discover(build_root: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in ("apk/**/*.apk", "bundle/**/*.aab"):
        found.extend(sorted(build_root.glob(pattern)))
    return [path for path in found if path.is_file()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Phase 6 APK/AAB artifacts.")
    parser.add_argument("--build-root", default=str(BUILD_ROOT))
    parser.add_argument("--output", default=str(DEFAULT_REPORT))
    parser.add_argument("--artifact", action="append", default=[])
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    artifacts = [Path(item) for item in args.artifact] if args.artifact else discover(Path(args.build_root))
    reports = [audit_archive(path) for path in artifacts]
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({"artifacts": reports}, ensure_ascii=False, indent=2), encoding="utf-8")
    for report in reports:
        print(f"{Path(report['artifact']).name}: {report['bytes']:,} bytes sha256={report['sha256'][:16]}… "
              f"abis={','.join(report['abis']) or 'n/a'} checks={report['passed']}")
    print(f"report: {destination}")


if __name__ == "__main__":
    main()
