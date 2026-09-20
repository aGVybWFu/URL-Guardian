from __future__ import annotations

import argparse
import shutil
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.official_downloader import (
    download_official_source,
    fetch_tranco_list_id,
    redacted_official_url,
    urlhaus_export_url,
)
from src.data.acquisition import record_acquisition_status
from src.data.snapshot import update_snapshot_metadata
from src.data.sources import PARSERS
from src.utils.config import PROJECT_ROOT
from src.utils.logging import configure_logging, get_logger
from src.utils.env import load_secret_environment

LOGGER = get_logger(__name__)
SOURCE_CONFIG = {
    "tranco": ("benign", "tranco.csv.zip"),
    "phishtank": ("phishing", "online-valid.csv.bz2"),
    "urlhaus": ("malware", "recent.csv"),
    "commoncrawl": ("benign", "commoncrawl.jsonl"),
    "openphish": ("phishing", "openphish-community.txt"),
    "cert_polska": ("phishing", "domains.json"),
    "threatfox": ("malware", "threatfox_iocs.json"),
    "phishing_database": ("phishing", "phishing-domains-ACTIVE.txt"),
}


def _parse(source: str, path: Path, collected_at: str, source_version: str | None):
    parser = PARSERS[source]
    if source == "tranco":
        return parser(path, list_id=source_version or "unknown", collected_at=collected_at)
    return parser(path, collected_at=collected_at)


def import_feed(
    source: str,
    input_path: str | Path,
    collected_at: str | None = None,
    source_version: str | None = None,
    snapshot: bool = False,
) -> Path:
    if source not in SOURCE_CONFIG:
        raise ValueError(f"Unsupported source: {source}")
    original = Path(input_path).resolve(strict=True)
    if not original.is_file():
        raise ValueError("Input must be a local file")
    day = collected_at or date.today().isoformat()
    path = original
    if snapshot:
        snapshot_dir = PROJECT_ROOT / "data" / "raw" / "snapshots" / day / source
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        path = snapshot_dir / original.name
        if original != path:
            shutil.copy2(original, path)
    frame = _parse(source, path, day, source_version)
    folder, _ = SOURCE_CONFIG[source]
    output_dir = PROJECT_ROOT / "data" / "raw" / folder
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{source}_{day}.csv"
    frame.to_csv(output, index=False)
    if snapshot:
        update_snapshot_metadata(path.parent.parent, source, path, len(frame), source_version)
    LOGGER.info("Imported %d rows from %s into %s", len(frame), source, output)
    return output


def download_and_import(source: str, day: str, variant: str = "recent") -> Path:
    if source == "commoncrawl":
        raise ValueError("Use scripts/collect_commoncrawl.py for Common Crawl candidates")
    if source == "threatfox":
        raise ValueError("Use scripts/collect_threatfox.py for the ThreatFox IOC API")
    _, filename = SOURCE_CONFIG[source]
    if source == "urlhaus":
        filename = f"{variant}.csv"
    source_dir = PROJECT_ROOT / "data" / "raw" / "snapshots" / day / source
    if source == "urlhaus":
        path, endpoint = download_official_source(urlhaus_export_url(variant), source_dir / filename)
    else:
        path, endpoint = download_official_source(source, source_dir / filename)
    source_version = fetch_tranco_list_id() if source == "tranco" else None
    frame = _parse(source, path, day, source_version)
    output_dir = PROJECT_ROOT / "data" / "raw" / SOURCE_CONFIG[source][0]
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{source}_{variant}_{day}.csv" if source == "urlhaus" else output_dir / f"{source}_{day}.csv"
    frame.to_csv(output, index=False, lineterminator="\n")
    update_snapshot_metadata(
        source_dir.parent,
        source,
        path,
        len(frame),
        source_version,
        endpoint,
    )
    LOGGER.info("Downloaded and imported %d %s records", len(frame), source)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Download an allowlisted official feed or snapshot a local feed")
    parser.add_argument("--source", required=True, choices=sorted(SOURCE_CONFIG))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--download", action="store_true", help="Download from the source's official endpoint")
    mode.add_argument("--input", help="Local official feed file to snapshot and import")
    parser.add_argument("--collected-at", default=date.today().isoformat(), help="Snapshot date (YYYY-MM-DD)")
    parser.add_argument("--source-version", default=None, help="Tranco list ID or other source version")
    parser.add_argument(
        "--variant",
        default="recent",
        choices=["recent", "full", "active"],
        help="URLhaus export variant; ignored for other sources",
    )
    args = parser.parse_args()
    configure_logging()
    if args.source in {"urlhaus", "phishtank", "threatfox"}:
        load_secret_environment(PROJECT_ROOT / ".env")
    status_path = PROJECT_ROOT / "reports" / "source_acquisition_status.json"
    try:
        output = (
            download_and_import(args.source, args.collected_at, args.variant)
            if args.download
            else import_feed(
                args.source,
                args.input,
                args.collected_at,
                args.source_version,
                snapshot=True,
            )
        )
        record_acquisition_status(
            status_path,
            args.source,
            "SUCCESS",
            f"Imported official snapshot for {args.collected_at}",
            f"snapshot-{args.collected_at}",
        )
        print(output)
    except (OSError, RuntimeError, ValueError) as error:
        detail = str(error)
        if args.source == "urlhaus" and "authentication" in detail.lower():
            detail = "URLhaus authentication failed"
        elif args.source == "urlhaus":
            detail = "URLhaus download failed"
        record_acquisition_status(status_path, args.source, "FAILED", detail)
        LOGGER.error("%s", detail)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
