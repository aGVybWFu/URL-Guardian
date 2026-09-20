"""Phishing.Database provider and OpenPhish accumulation tests."""

from pathlib import Path

import pandas as pd
import pytest

from src.data.openphish_accumulation import accumulate, discover_snapshots
from src.data.snapshot import sha256_file
from src.data.sources import PhishingDatabaseProvider, parse_phishing_database

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_phishing_database_parser_builds_https_domain_rows(tmp_path):
    feed = tmp_path / "phishing-domains-ACTIVE.txt"
    feed.write_text("evil.example\nbad.example.org\n# comment\n\n", encoding="utf-8")
    frame = parse_phishing_database(feed, "2026-09-20")
    assert frame["url"].tolist() == ["https://evil.example/", "https://bad.example.org/"]
    assert set(frame["label"]) == {"PHISHING"}
    assert set(frame["source"]) == {"phishing_database"}
    assert set(frame["label_confidence"]) == {"community_report"}
    assert PhishingDatabaseProvider().parse(feed, "2026-09-20").equals(frame)


def test_phishing_database_parser_rejects_an_empty_feed(tmp_path):
    feed = tmp_path / "empty.txt"
    feed.write_text("# only comments\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        parse_phishing_database(feed, "2026-09-20")


def test_phishing_database_records_are_community_reports_not_ground_truth(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("maybe-phishing.example\n", encoding="utf-8")
    frame = parse_phishing_database(feed, "2026-09-20")
    assert frame.loc[0, "label_confidence"] == "community_report"


def test_openphish_accumulation_deduplicates_repeated_urls(tmp_path):
    from src.data.openphish_accumulation import SnapshotEvidence

    day_one = tmp_path / "2026-09-01.txt"
    day_two = tmp_path / "2026-09-02.txt"
    day_one.write_text("https://a.example/login\nhttps://b.example/verify\n", encoding="utf-8")
    day_two.write_text("https://a.example/login\nhttps://c.example/secure\n", encoding="utf-8")
    snapshots = [
        SnapshotEvidence("2026-09-01", day_one.as_posix(), sha256_file(day_one), 2),
        SnapshotEvidence("2026-09-02", day_two.as_posix(), sha256_file(day_two), 2),
    ]
    result = accumulate(snapshots)
    assert result.total_raw_records == 4
    assert result.unique_normalized_urls == 3
    assert result.duplicate_url_occurrences == 1
    assert result.unique_registrable_domains == 3
    assert result.to_dict()["snapshotCount"] == 2
    assert "counted once" in result.to_dict()["deduplicationRule"]


def test_openphish_accumulation_collapses_urls_on_one_registrable_domain(tmp_path):
    from src.data.openphish_accumulation import SnapshotEvidence

    feed = tmp_path / "feed.txt"
    feed.write_text(
        "https://a.example.com/login\nhttps://b.example.com/verify\nhttps://a.example.com/other\n",
        encoding="utf-8",
    )
    snapshots = [SnapshotEvidence("2026-09-20", feed.as_posix(), sha256_file(feed), 3)]
    result = accumulate(snapshots)
    assert result.unique_normalized_urls == 3
    assert result.unique_registrable_domains == 1


def test_openphish_accumulation_records_snapshot_evidence(tmp_path):
    from src.data.openphish_accumulation import SnapshotEvidence

    feed = tmp_path / "feed.txt"
    feed.write_text("https://a.example/\n", encoding="utf-8")
    snapshots = [SnapshotEvidence("2026-09-20", feed.as_posix(), sha256_file(feed), 1)]
    payload = accumulate(snapshots).to_dict()
    evidence = payload["snapshots"][0]
    assert evidence["snapshotDate"] == "2026-09-20"
    assert evidence["sha256"] == sha256_file(feed)
    assert evidence["recordCount"] == 1


def test_official_openphish_accumulation_matches_the_metadata():
    metadata_path = REPO_ROOT / "data" / "processed" / "v1.3.0" / "dataset_metadata.json"
    if not metadata_path.exists():
        pytest.skip("dataset-v1.3.0 is not built in this environment")
    import json

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    accumulation = metadata["openphishAccumulation"]
    snapshots = discover_snapshots(REPO_ROOT / "data" / "raw")
    if not snapshots:
        pytest.skip("OpenPhish snapshots are not present")
    assert accumulation["snapshotCount"] == len(snapshots)
    assert accumulation["totalRawRecords"] == sum(item.record_count for item in snapshots)
