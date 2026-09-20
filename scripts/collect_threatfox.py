"""Acquire official abuse.ch ThreatFox IOCs as an immutable snapshot.

Only the documented HTTPS API at `threatfox-api.abuse.ch/api/v1/` is used, with
the `Auth-Key` supplied as a request header. The credential therefore never
enters a URL, a snapshot path, an error message, a log line or metadata.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.acquisition import record_acquisition_status
from src.data.official_downloader import OfficialDownloadError, fetch_threatfox_iocs
from src.data.snapshot import update_snapshot_metadata
from src.data.sources import parse_threatfox
from src.utils.config import PROJECT_ROOT
from src.utils.env import load_secret_environment, threatfox_auth_key
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
DEFAULT_THREAT_TYPES = ("payload_delivery",)


def collect(
    snapshot_date: str,
    days: int = 7,
    threat_types: tuple[str, ...] = DEFAULT_THREAT_TYPES,
) -> Path:
    """Fetch, snapshot and standardize the ThreatFox domain IOC set."""

    auth_key, key_source = threatfox_auth_key()
    if not auth_key:
        raise OfficialDownloadError(
            "No abuse.ch Auth-Key is configured (THREATFOX_AUTH_KEY or URLHAUS_AUTH_KEY)"
        )
    response = fetch_threatfox_iocs(days=days, auth_key=auth_key)
    status = str(response.get("query_status", "unknown"))
    records = response.get("data")
    if status != "ok" or not isinstance(records, list):
        raise OfficialDownloadError("ThreatFox query did not return a successful IOC list")

    snapshot_dir = PROJECT_ROOT / "data" / "raw" / "snapshots" / snapshot_date / "threatfox"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    raw_path = snapshot_dir / "threatfox_iocs.json"
    serialized = json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True)
    if raw_path.exists():
        if raw_path.read_text(encoding="utf-8") != serialized:
            raise RuntimeError("Immutable snapshot already contains different ThreatFox content")
    else:
        raw_path.write_text(serialized, encoding="utf-8")

    frame = parse_threatfox(response, snapshot_date, threat_types)
    output_dir = PROJECT_ROOT / "data" / "raw" / "malware"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"threatfox_{snapshot_date}.csv"
    frame.to_csv(output, index=False, lineterminator="\n")

    update_snapshot_metadata(
        snapshot_dir.parent,
        "threatfox",
        raw_path,
        len(frame),
        f"get_iocs_days_{int(days)}",
        None,
    )
    LOGGER.info(
        "Imported %d ThreatFox domain IOCs for threat types %s",
        len(frame),
        ",".join(threat_types),
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect official ThreatFox domain IOCs")
    parser.add_argument("--snapshot-date", default=date.today().isoformat())
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--threat-types", default=",".join(DEFAULT_THREAT_TYPES))
    args = parser.parse_args()
    configure_logging()
    load_secret_environment(PROJECT_ROOT / ".env")
    status_path = PROJECT_ROOT / "reports" / "source_acquisition_status.json"
    threat_types = tuple(value.strip() for value in args.threat_types.split(",") if value.strip())
    try:
        if not 1 <= args.days <= 7:
            raise ValueError("ThreatFox days must be between 1 and 7")
        output = collect(args.snapshot_date, args.days, threat_types)
        record_acquisition_status(
            status_path,
            "threatfox",
            "SUCCESS",
            f"Imported {int(args.days)}-day ThreatFox domain IOCs for {','.join(threat_types)}",
            f"snapshot-{args.snapshot_date}",
        )
        print(output)
    except (OfficialDownloadError, OSError, RuntimeError, ValueError) as error:
        detail = str(error)
        if "authentication" in detail.lower():
            detail = "ThreatFox authentication failed"
        elif "threatfox" in detail.lower():
            detail = "ThreatFox request failed"
        record_acquisition_status(status_path, "threatfox", "FAILED", detail)
        LOGGER.error("%s", detail)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
