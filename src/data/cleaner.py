from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from .normalizer import URLNormalizationError, normalize_url

VALID_LABELS = {"BENIGN", "PHISHING", "MALWARE"}


@dataclass
class CleaningStats:
    raw_rows: int = 0
    removed_empty: int = 0
    removed_invalid_label: int = 0
    removed_exact_duplicates: int = 0
    removed_invalid_urls: int = 0
    removed_normalized_duplicates: int = 0
    removed_conflicts: int = 0
    remaining_rows: int = 0
    class_distribution: dict[str, int] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def clean_dataset(frame: pd.DataFrame, conflicts_path: str | Path) -> tuple[pd.DataFrame, CleaningStats]:
    required = {"url", "label", "source", "collected_at"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")
    stats = CleaningStats(raw_rows=len(frame))
    work = frame.copy()
    work["url"] = work["url"].astype("string").str.strip()
    work["label"] = work["label"].astype("string").str.strip().str.upper()
    work["source"] = work["source"].astype("string").str.strip()

    empty_mask = work["url"].isna() | work["url"].eq("") | work["source"].isna() | work["source"].eq("")
    stats.removed_empty = int(empty_mask.sum())
    work = work.loc[~empty_mask].copy()
    invalid_label = ~work["label"].isin(VALID_LABELS)
    stats.removed_invalid_label = int(invalid_label.sum())
    work = work.loc[~invalid_label].copy()
    duplicate_mask = work.duplicated(subset=["url", "label"], keep="first")
    stats.removed_exact_duplicates = int(duplicate_mask.sum())
    work = work.loc[~duplicate_mask].copy()

    parsed_rows: list[dict[str, object]] = []
    invalid_count = 0
    for _, row in work.iterrows():
        try:
            parsed = normalize_url(row["url"])
            if len(parsed.normalized_url) < 8:
                raise URLNormalizationError("URL is too short")
            parsed_rows.append(
                {
                    **row.to_dict(),
                    **parsed.to_dict(),
                    "label": row["label"],
                    "source": row["source"],
                    "collected_at": row["collected_at"],
                }
            )
        except (URLNormalizationError, TypeError, ValueError):
            invalid_count += 1
    stats.removed_invalid_urls = invalid_count
    clean = pd.DataFrame(parsed_rows)
    if clean.empty:
        conflict_columns = ["original_url", "normalized_url", "label", "source", "collected_at"]
        Path(conflicts_path).parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(columns=conflict_columns).to_csv(conflicts_path, index=False)
        stats.class_distribution = {}
        return clean, stats

    label_counts = clean.groupby("normalized_url")["label"].nunique()
    conflict_urls = set(label_counts[label_counts > 1].index)
    conflicts = clean[clean["normalized_url"].isin(conflict_urls)].copy()
    Path(conflicts_path).parent.mkdir(parents=True, exist_ok=True)
    conflicts.to_csv(conflicts_path, index=False)
    stats.removed_conflicts = len(conflicts)
    clean = clean[~clean["normalized_url"].isin(conflict_urls)].copy()
    normalized_dupes = clean.duplicated(subset=["normalized_url"], keep="first")
    stats.removed_normalized_duplicates = int(normalized_dupes.sum())
    clean = clean.loc[~normalized_dupes].reset_index(drop=True)
    stats.remaining_rows = len(clean)
    stats.class_distribution = {str(k): int(v) for k, v in clean["label"].value_counts().sort_index().items()}
    return clean, stats
