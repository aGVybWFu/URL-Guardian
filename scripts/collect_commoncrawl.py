from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.download_data import import_feed
from src.data.acquisition import record_acquisition_status
from src.data.commoncrawl import collect_candidates
from src.data.snapshot import update_snapshot_metadata
from src.utils.config import PROJECT_ROOT
from src.utils.config import load_config
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def main() -> None:
    configure_logging()
    config = load_config()
    commoncrawl_config = config.get("commoncrawl", {})
    parser = argparse.ArgumentParser(
        description="Query only Common Crawl index metadata for URL candidates associated with Tranco domains"
    )
    parser.add_argument("--tranco", required=True, help="Local standardized Tranco CSV")
    parser.add_argument("--limit-domains", type=int, default=int(commoncrawl_config.get("max_domains", 5000)))
    parser.add_argument(
        "--candidate-pool-size", type=int, default=int(commoncrawl_config.get("candidate_pool_size", 50000))
    )
    parser.add_argument("--per-domain", type=int, default=int(commoncrawl_config.get("max_urls_per_domain", 5)))
    parser.add_argument("--delay", type=float, default=float(commoncrawl_config.get("delay_seconds", 0.2)))
    parser.add_argument("--index-id", default=commoncrawl_config.get("index_id"))
    parser.add_argument("--workers", type=int, default=int(commoncrawl_config.get("workers", 4)))
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--snapshot-date", default=date.today().isoformat())
    args = parser.parse_args()
    try:
        if (
            args.limit_domains <= 0
            or args.candidate_pool_size < args.limit_domains
            or args.per_domain <= 0
            or args.delay < 0
            or args.workers <= 0
        ):
            raise ValueError("Common Crawl limits must be positive and delay cannot be negative")
        tranco = pd.read_csv(Path(args.tranco), dtype=str)
        domain_column = "domain" if "domain" in tranco else "url"
        domains = tranco[domain_column].dropna().astype(str).str.replace(r"^https?://", "", regex=True)
        domains = domains.str.split("/").str[0].drop_duplicates().head(args.candidate_pool_size)
        if len(domains) > args.limit_domains:
            domains = domains.sample(n=args.limit_domains, random_state=int(config["random_seed"])).sort_index()
        domains = domains.tolist()
        source_dir = PROJECT_ROOT / "data" / "raw" / "snapshots" / args.snapshot_date / "commoncrawl"
        path, index_id, count, failures = collect_candidates(
            domains,
            source_dir / "commoncrawl_candidates.jsonl",
            args.per_domain,
            args.delay,
            args.index_id,
            args.workers,
            args.resume,
        )
        if count == 0:
            raise RuntimeError(
                f"Common Crawl returned no usable candidates; per-domain failures={failures}"
            )
        update_snapshot_metadata(source_dir.parent, "commoncrawl", path, count, index_id)
        output = import_feed("commoncrawl", path, args.snapshot_date, index_id, snapshot=False)
        if failures:
            LOGGER.warning("Common Crawl recorded %d per-domain query failures in the snapshot", failures)
        record_acquisition_status(
            PROJECT_ROOT / "reports" / "source_acquisition_status.json",
            "commoncrawl",
            "SUCCESS",
            f"Collected {count} candidates from {index_id}; per-domain failures={failures}",
            f"snapshot-{args.snapshot_date}",
        )
        print(output)
    except (OSError, RuntimeError, ValueError) as error:
        record_acquisition_status(
            PROJECT_ROOT / "reports" / "source_acquisition_status.json",
            "commoncrawl",
            "FAILED",
            str(error),
        )
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
