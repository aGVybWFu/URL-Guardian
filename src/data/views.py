from __future__ import annotations

import ipaddress
from pathlib import Path

import pandas as pd


def _domain_url(hostname: str) -> str:
    try:
        value = ipaddress.ip_address(hostname)
        host = f"[{hostname}]" if value.version == 6 else hostname
    except ValueError:
        host = hostname
    return f"https://{host}/"


def _drop_representation_conflicts(frame: pd.DataFrame, output: str | Path) -> pd.DataFrame:
    counts = frame.groupby("model_url")["label"].nunique()
    conflict_keys = set(counts[counts > 1].index)
    conflicts = frame[frame["model_url"].isin(conflict_keys)].copy()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    conflicts.to_csv(path, index=False)
    return frame[~frame["model_url"].isin(conflict_keys)].copy()


def create_domain_only_view(frame: pd.DataFrame, conflicts_path: str | Path) -> pd.DataFrame:
    view = frame.copy()
    view["model_url"] = view["registrable_domain"].map(_domain_url)
    view["dataset_view"] = "DOMAIN_ONLY"
    view = _drop_representation_conflicts(view, conflicts_path)
    return view.drop_duplicates(subset=["model_url", "label"], keep="first").reset_index(drop=True)


def create_full_url_view(
    frame: pd.DataFrame,
    approved_sources: dict[str, set[str]] | None = None,
) -> pd.DataFrame:
    sources = approved_sources or {
        "BENIGN": {"commoncrawl_tranco_candidate"},
        "PHISHING": {"openphish", "phishtank"},
        "MALWARE": {"urlhaus"},
    }
    allowed = pd.Series(False, index=frame.index)
    for label, source_names in sources.items():
        allowed |= frame["label"].eq(label) & frame["source"].isin(source_names)
    view = frame[allowed].copy()
    view["model_url"] = view["normalized_url"]
    view["dataset_view"] = "FULL_URL"
    return view.drop_duplicates(subset=["model_url", "label"], keep="first").reset_index(drop=True)


def sample_per_class(frame: pd.DataFrame, target: int, seed: int) -> pd.DataFrame:
    parts = []
    for label, group in frame.groupby("label", sort=True):
        count = min(len(group), target)
        parts.append(group.sample(n=count, random_state=seed) if len(group) > count else group.copy())
    if not parts:
        return frame.copy()
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def write_domain_label_conflicts(frame: pd.DataFrame, output: str | Path) -> int:
    counts = frame.groupby("registrable_domain")["label"].nunique()
    domains = set(counts[counts > 1].index)
    conflicts = frame[frame["registrable_domain"].isin(domains)].copy()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    conflicts.to_csv(path, index=False)
    return len(domains)
