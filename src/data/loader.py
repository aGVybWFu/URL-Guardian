from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

LABEL_BY_FOLDER = {"benign": "BENIGN", "phishing": "PHISHING", "malware": "MALWARE"}


def _read_text(path: Path) -> pd.DataFrame:
    rows: list[str] = []
    for line in path.read_text(encoding="utf-8-sig", errors="strict").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        rows.append(parts[1] if len(parts) >= 2 and parts[0].isdigit() else parts[0])
    return pd.DataFrame({"url": rows})


def _read_file(path: Path) -> pd.DataFrame:
    suffixes = "".join(path.suffixes).lower()
    if ".csv" in suffixes:
        return pd.read_csv(path, comment="#", dtype=str, on_bad_lines="error")
    if suffixes.endswith(".jsonl"):
        return pd.read_json(path, lines=True, dtype=False)
    if ".json" in suffixes:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            data = data.get("entries", data.get("data", [data]))
        return pd.DataFrame(data)
    if suffixes.endswith((".txt", ".list")):
        return _read_text(path)
    raise ValueError(f"Unsupported raw file: {path.name}")


def _find_column(frame: pd.DataFrame, candidates: tuple[str, ...]) -> str | None:
    lookup = {str(column).strip().lower(): str(column) for column in frame.columns}
    return next((lookup[name] for name in candidates if name in lookup), None)


def load_raw_dataset(raw_root: str | Path) -> pd.DataFrame:
    root = Path(raw_root)
    records: list[pd.DataFrame] = []
    for folder, default_label in LABEL_BY_FOLDER.items():
        directory = root / folder
        for path in sorted(directory.glob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            frame = _read_file(path)
            url_column = _find_column(frame, ("url", "domain", "hostname"))
            if not url_column:
                raise ValueError(f"No URL/domain column in {path}")
            label_column = _find_column(frame, ("label", "class"))
            source_column = _find_column(frame, ("source",))
            date_column = _find_column(frame, ("collected_at", "submission_time", "dateadded", "date_added"))
            urls = frame[url_column].astype("string")
            if url_column.lower() in {"domain", "hostname"}:
                urls = "https://" + urls.str.strip()
            loaded = frame.copy()
            if url_column != "url":
                loaded = loaded.rename(columns={url_column: "url"})
            loaded["url"] = urls
            loaded["label"] = frame[label_column] if label_column else default_label
            loaded["source"] = frame[source_column] if source_column else path.stem.split(".")[0]
            loaded["collected_at"] = frame[date_column] if date_column else pd.NA
            records.append(loaded)
    if not records:
        return pd.DataFrame(columns=["url", "label", "source", "collected_at"])
    return pd.concat(records, ignore_index=True)
