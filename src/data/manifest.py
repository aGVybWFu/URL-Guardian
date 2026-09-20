from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from .snapshot import sha256_file


def _domain_assignment_hash(views: dict[str, pd.DataFrame]) -> str:
    assignments: set[str] = set()
    for view, frame in views.items():
        for domain in frame["registrable_domain"].dropna().astype(str):
            assignments.add(f"{view}:{domain}")
    return hashlib.sha256("\n".join(sorted(assignments)).encode("utf-8")).hexdigest()


def _csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False, lineterminator="\n").encode("utf-8")


def build_test_manifest(
    dataset_version: str,
    test_frames: dict[str, pd.DataFrame],
    split_seed: int,
) -> dict[str, object]:
    views: dict[str, dict[str, object]] = {}
    for view, frame in sorted(test_frames.items()):
        views[view] = {
            "sha256": hashlib.sha256(_csv_bytes(frame)).hexdigest(),
            "record_count": len(frame),
            "domain_count": int(frame["registrable_domain"].nunique()),
            "file": f"{view}/test.csv",
        }
    combined = "\n".join(f"{view}:{entry['sha256']}" for view, entry in sorted(views.items()))
    return {
        "manifestSchemaVersion": 2,
        "datasetVersion": dataset_version,
        "combinedTestSetSha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        "domainAssignmentSha256": _domain_assignment_hash(test_frames),
        "splitSeed": int(split_seed),
        "views": views,
    }


def verify_test_manifest_candidate(manifest_path: str | Path, candidate: dict[str, object]) -> None:
    path = Path(manifest_path)
    if not path.exists():
        return
    existing = json.loads(path.read_text(encoding="utf-8"))
    comparable = {key: value for key, value in existing.items() if key != "creationTime"}
    if comparable != candidate:
        raise RuntimeError(
            "The sealed test set differs from test_manifest.json. Archive it under a new dataset version; "
            "do not redraw the existing Test Set."
        )


def seal_test_manifest(manifest_path: str | Path, candidate: dict[str, object]) -> dict[str, object]:
    path = Path(manifest_path)
    verify_test_manifest_candidate(path, candidate)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    manifest = {
        **candidate,
        "creationTime": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def create_or_verify_test_manifest(
    manifest_path: str | Path,
    dataset_version: str,
    test_files: dict[str, str | Path],
) -> dict[str, object]:
    frames: dict[str, pd.DataFrame] = {}
    for view, value in sorted(test_files.items()):
        path = Path(value)
        frame = pd.read_csv(path)
        frames[view] = frame
    candidate = build_test_manifest(dataset_version, frames, split_seed=42)
    for view, value in sorted(test_files.items()):
        candidate["views"][view]["sha256"] = sha256_file(value)  # type: ignore[index]
    combined = "\n".join(
        f"{view}:{entry['sha256']}" for view, entry in sorted(candidate["views"].items())  # type: ignore[union-attr]
    )
    candidate["combinedTestSetSha256"] = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return seal_test_manifest(manifest_path, candidate)
