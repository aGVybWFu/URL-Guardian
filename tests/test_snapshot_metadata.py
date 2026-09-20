import hashlib
import json

import pytest

from src.data.snapshot import update_snapshot_metadata


def test_snapshot_metadata_records_hash_size_count_and_version(tmp_path):
    snapshot = tmp_path / "2026-09-20"
    source = snapshot / "tranco" / "feed.csv"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"1,example.com\n")
    metadata = update_snapshot_metadata(snapshot, "tranco", source, 1, "LIST-ID")
    entry = metadata["sources"][0]
    assert entry["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert entry["file_size"] == source.stat().st_size
    assert entry["record_count"] == 1
    assert entry["source_version"] == "LIST-ID"
    persisted = json.loads((snapshot / "snapshot_metadata.json").read_text(encoding="utf-8"))
    assert persisted["snapshot_id"] == "snapshot-2026-09-20"


def test_snapshot_source_cannot_be_overwritten_with_different_content(tmp_path):
    snapshot = tmp_path / "2026-09-20"
    snapshot.mkdir()
    feed = snapshot / "feed.txt"
    feed.write_text("first", encoding="utf-8")
    update_snapshot_metadata(snapshot, "openphish", feed, 1, "community")
    feed.write_text("second", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Immutable snapshot"):
        update_snapshot_metadata(snapshot, "openphish", feed, 1, "community")
