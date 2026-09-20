"""Audit a URL Guardian APK: size breakdown, ABI contents and hardening checks."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = Path.home() / "ug-build" / "URLGuardianAndroid" / "app" / "outputs" / "apk" / "debug" / "app-debug.apk"
DEFAULT_REPORT = ROOT / "reports" / "deployment" / "apk_size_audit.json"
ALLOWED_ABIS = {"arm64-v8a", "x86_64"}
FORBIDDEN_ASSET_SUFFIXES = (
    "golden_set.json", "policy_v2_golden.json", "parity_report.json",
    "feature_schema.json", "output_schema.json", "deployment_manifest.json",
    "decision_policy.json",
)


def audit(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as archive:
        entries = [
            {"name": info.filename, "size": info.file_size, "compressed": info.compress_size}
            for info in archive.infolist() if not info.is_dir()
        ]

    def total(predicate) -> int:
        return sum(entry["size"] for entry in entries if predicate(entry["name"]))

    libs = [entry for entry in entries if entry["name"].startswith("lib/")]
    abis = sorted({entry["name"].split("/")[1] for entry in libs})
    assets = sorted((entry for entry in entries if entry["name"].startswith("assets/")), key=lambda e: -e["size"])
    dex = [entry for entry in entries if entry["name"].startswith("classes") and entry["name"].endswith(".dex")]
    categories = {
        "nativeLibs": total(lambda name: name.startswith("lib/")),
        "assets": total(lambda name: name.startswith("assets/")),
        "dex": total(lambda name: name.endswith(".dex")),
        "resources": total(lambda name: name.startswith("res/")),
        "metaInf": total(lambda name: name.startswith("META-INF/")),
        "other": 0,
    }
    categories["other"] = sum(entry["size"] for entry in entries) - sum(categories.values())
    checks = {
        "onlyAllowedAbis": set(abis) <= ALLOWED_ABIS,
        "bothTargetAbisPresent": ALLOWED_ABIS <= set(abis),
        "noUnexpectedNativeLibs": all(entry["name"].endswith(".so") for entry in libs),
        "noTestOnlyAssets": not any(entry["name"].endswith(FORBIDDEN_ASSET_SUFFIXES) for entry in entries),
    }
    return {
        "apk": str(apk),
        "apkBytes": apk.stat().st_size,
        "uncompressedBytes": sum(entry["size"] for entry in entries),
        "compressedPayloadBytes": sum(entry["compressed"] for entry in entries),
        "categories": categories,
        "abis": abis,
        "abiBytes": {abi: sum(entry["size"] for entry in libs if entry["name"].split("/")[1] == abi) for abi in abis},
        "nativeLibs": [{"name": entry["name"], "size": entry["size"]} for entry in sorted(libs, key=lambda e: -e["size"])],
        "assets": [{"name": entry["name"], "size": entry["size"]} for entry in assets],
        "dexFiles": [{"name": entry["name"], "size": entry["size"]} for entry in dex],
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the URL Guardian APK.")
    parser.add_argument("--apk", default=str(DEFAULT_APK))
    parser.add_argument("--output", default=str(DEFAULT_REPORT))
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = audit(Path(args.apk))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"APK: {report['apkBytes']:,} bytes; uncompressed {report['uncompressedBytes']:,} bytes")
    print(f"ABIs: {', '.join(report['abis'])} -> {report['abiBytes']}")
    for name, size in report["categories"].items():
        print(f"  {name}: {size:,} bytes")
    print(f"checks passed: {report['passed']} ({report['checks']})")
    print(f"report: {destination}")


if __name__ == "__main__":
    main()
