from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_id(day: str) -> str:
    return f"snapshot-{day}"


def update_snapshot_metadata(
    snapshot_dir: str | Path,
    source: str,
    file_path: str | Path,
    record_count: int,
    source_version: str | None = None,
    download_url: str | None = None,
) -> dict[str, Any]:
    directory = Path(snapshot_dir)
    directory.mkdir(parents=True, exist_ok=True)
    metadata_path = directory / "snapshot_metadata.json"
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    else:
        metadata = {
            "snapshot_id": snapshot_id(directory.name),
            "download_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": [],
        }
    path = Path(file_path)
    entry = {
        "source": source,
        "source_version": source_version,
        "file": path.relative_to(directory).as_posix(),
        "sha256": sha256_file(path),
        "file_size": path.stat().st_size,
        "record_count": int(record_count),
        "acquired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if download_url:
        entry["official_endpoint"] = download_url
    existing = next((item for item in metadata.get("sources", []) if item.get("source") == source), None)
    if existing:
        stable_fields = ("source", "source_version", "file", "sha256", "file_size", "record_count")
        if any(existing.get(field) != entry.get(field) for field in stable_fields):
            raise RuntimeError("Immutable snapshot already contains different metadata for this source")
        return metadata
    metadata["sources"].append(entry)
    metadata["sources"] = sorted(metadata["sources"], key=lambda item: item["source"])
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return metadata


def load_snapshot_catalog(raw_root: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    snapshots = Path(raw_root) / "snapshots"
    for metadata_path in sorted(snapshots.glob("*/snapshot_metadata.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        entries.append(metadata)
    return entries
