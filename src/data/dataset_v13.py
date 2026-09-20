"""dataset-v1.3.0: binary phishing dataset (BENIGN / PHISHING).

Scope refinement rationale:

* Phase 2.5 proved that URL-only `DOMAIN_ONLY` representations do not generalise
  to domain-hosted malware (non-IP MALWARE recall 3-5%, ThreatFox source-holdout
  0.27%). MALWARE is therefore removed from the ML label space and handled by the
  Threat Intelligence layer instead.
* The remaining ML task is binary: `0 = BENIGN`, `1 = PHISHING`.

`dataset-v1.1.0` and `dataset-v1.2.0` are never touched. Everything here is
written under versioned v1.3.0 paths.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.data.cleaner import clean_dataset
from src.data.loader import load_raw_dataset
from src.data.manifest import build_test_manifest, seal_test_manifest, verify_test_manifest_candidate
from src.data.openphish_accumulation import accumulate, discover_snapshots, write_accumulation_report
from src.data.snapshot import load_snapshot_catalog
from src.data.splitter import assert_no_domain_leakage, domain_aware_split
from src.data.views import create_domain_only_view, sample_per_class, write_domain_label_conflicts
from src.utils.config import load_config, project_path

DATASET_VERSION = "dataset-v1.3.0"
BINARY_LABELS = {"BENIGN", "PHISHING"}
BINARY_LABEL_MAPPING = {"BENIGN": 0, "PHISHING": 1}
PHISHING_SOURCES = ("cert_polska", "openphish", "phishing_database")
LARGE_SOURCES = ("tranco", "cert_polska", "phishing_database")
DEFAULT_MAX_SOURCE_SHARE = 0.5


def _distribution(frame: pd.DataFrame, column: str = "label") -> dict[str, int]:
    return {str(key): int(value) for key, value in frame[column].value_counts().sort_index().items()}


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def preselect_binary_sources(
    raw: pd.DataFrame, target: int, seed: int, multiplier: int
) -> pd.DataFrame:
    """Deterministic per-source cap so very large feeds do not dominate cleaning cost."""

    cap = target * multiplier
    parts: list[pd.DataFrame] = []
    for source, group in raw.groupby("source", sort=True, dropna=False):
        if source in LARGE_SOURCES and len(group) > cap:
            group = group.sample(n=cap, random_state=seed)
        parts.append(group)
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def capped_source_sample(
    frame: pd.DataFrame,
    label: str,
    target: int,
    max_source_share: float,
    seed: int,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Sample one label with a per-source cap so no single feed dominates.

    Every source is offered an equal cap. Sources with less data contribute
    everything they have, and the remaining budget is redistributed to sources
    that still have records. No row is duplicated or synthesised.
    """

    subset = frame[frame["label"].astype(str) == label]
    if subset.empty:
        raise ValueError(f"No rows available for label {label}")
    if not 0 < max_source_share <= 1:
        raise ValueError("max_source_share must be in (0, 1]")
    cap = max(1, int(target * max_source_share))
    pools: dict[str, pd.DataFrame] = {
        str(source): group for source, group in subset.groupby("source", sort=True)
    }
    remaining = dict.fromkeys(pools, cap)
    chosen: list[pd.DataFrame] = []
    budget = target
    while budget > 0 and any(remaining[source] > 0 and len(pools[source]) > 0 for source in pools):
        progressed = False
        for source in sorted(pools):
            if budget <= 0:
                break
            available = len(pools[source])
            if available == 0 or remaining[source] <= 0:
                continue
            take = min(budget, remaining[source], available)
            if take <= 0:
                continue
            picked = pools[source].sample(n=take, random_state=seed)
            chosen.append(picked)
            pools[source] = pools[source].drop(index=picked.index)
            remaining[source] -= take
            budget -= take
            progressed = True
        if not progressed:
            break
    if not chosen:
        raise ValueError(f"Unable to sample any rows for label {label}")
    sampled = pd.concat(chosen, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    source_counts = _distribution(sampled, "source")
    return sampled, {
        "label": label,
        "target": target,
        "perSourceCap": cap,
        "maxSourceShare": max_source_share,
        "seed": seed,
        "sampledSourceDistribution": source_counts,
        "sampledShare": {key: value / max(1, len(sampled)) for key, value in source_counts.items()},
        "availableSourceDistribution": _distribution(subset, "source"),
        "syntheticRowsCreated": 0,
        "duplicateRowsCreated": 0,
        "method": "deterministic_equal_cap_then_redistribute",
    }


def cross_source_conflict_audit(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Report BENIGN versus PHISHING conflicts on the same normalized URL.

    Conflicting rows are excluded from the first training dataset. The report is
    kept so the conflict rate stays visible.
    """

    labels_per_url = frame.groupby("normalized_url")["label"].nunique()
    conflicting = set(labels_per_url[labels_per_url > 1].index)
    conflict_rows = frame[frame["normalized_url"].isin(conflicting)].copy()
    phishing_overlap = frame[frame["source"].isin(PHISHING_SOURCES)]
    domains_per_url = phishing_overlap.groupby("registrable_domain")["source"].nunique()
    multi_source_domains = domains_per_url[domains_per_url > 1]
    return conflict_rows, {
        "conflictingNormalizedUrls": int(len(conflicting)),
        "conflictingRows": int(len(conflict_rows)),
        "domainsListedByMultiplePhishingSources": int(len(multi_source_domains)),
        "rule": (
            "A normalized URL that appears as both BENIGN and PHISHING is excluded from the first "
            "binary training dataset and written to the conflict report."
        ),
    }


def _apply_shared_split(
    frame: pd.DataFrame, ratios: tuple[float, float, float], seed: int
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    parts = domain_aware_split(frame, *ratios, seed)
    assert_no_domain_leakage(*parts)
    return parts


def build_dataset_v13(config_path: str | Path | None = None) -> dict[str, Any]:
    """Build dataset-v1.3.0 with a frozen binary Test Set."""

    config = load_config(config_path)
    seed = int(config["random_seed"])
    target = int(config.get("dataset", {}).get("target_per_class", 20_000))
    multiplier = int(config.get("dataset", {}).get("preselection_multiplier", 2))
    max_share = float(config.get("dataset", {}).get("binary_max_source_share", DEFAULT_MAX_SOURCE_SHARE))
    ratios_config = config["split"]
    ratios = (
        float(ratios_config["train_ratio"]),
        float(ratios_config["validation_ratio"]),
        float(ratios_config["test_ratio"]),
    )
    raw_root = project_path(config["paths"]["raw"])
    raw_all = load_raw_dataset(raw_root)
    if raw_all.empty:
        raise RuntimeError("No formal raw data found for dataset-v1.3.0")

    malware_rows = raw_all[raw_all["label"].astype(str).str.upper() == "MALWARE"]
    binary_raw = raw_all[raw_all["label"].astype(str).str.upper() != "MALWARE"].copy()
    present = set(binary_raw["label"].astype(str).str.upper())
    missing = sorted(BINARY_LABELS.difference(present))
    if missing:
        raise RuntimeError(f"dataset-v1.3.0 requires BENIGN and PHISHING; missing: {missing}")

    processing_dir = project_path("data/processed/v1.3.0")
    processing_dir.mkdir(parents=True, exist_ok=True)

    openphish_snapshots = discover_snapshots(raw_root)
    openphish_accumulated = accumulate(openphish_snapshots, collected_at=None)
    write_accumulation_report(
        openphish_accumulated, processing_dir / "openphish_accumulation.json"
    )

    raw = preselect_binary_sources(binary_raw, target, seed, multiplier)
    clean, cleaning = clean_dataset(raw, project_path("reports/v1.3.0/conflicts.csv"))
    if clean.empty:
        raise RuntimeError("No usable rows remain after cleaning for dataset-v1.3.0")

    conflict_rows, conflict_audit = cross_source_conflict_audit(clean)
    conflict_path = project_path("reports/v1.3.0/benign_phishing_conflicts.csv")
    conflict_path.parent.mkdir(parents=True, exist_ok=True)
    conflict_rows.to_csv(conflict_path, index=False, lineterminator="\n")
    clean = clean[~clean["normalized_url"].isin(set(conflict_rows["normalized_url"]))].reset_index(drop=True)

    clean.to_csv(processing_dir / "cleaned_dataset.csv", index=False, lineterminator="\n")
    domain_conflicts = write_domain_label_conflicts(
        clean, project_path("reports/v1.3.0/domain_label_conflicts.csv")
    )

    domain_only_full = create_domain_only_view(
        clean, project_path("reports/v1.3.0/domain_only_conflicts.csv")
    )
    views_dir = processing_dir / "views"
    views_dir.mkdir(parents=True, exist_ok=True)
    domain_only_full.to_csv(views_dir / "domain_only_full.csv", index=False, lineterminator="\n")

    phishing_sample, phishing_rationale = capped_source_sample(
        domain_only_full, "PHISHING", target, max_share, seed
    )
    benign_frame = domain_only_full[domain_only_full["label"].astype(str) == "BENIGN"]
    benign_sample = sample_per_class(benign_frame, target, seed)
    benign_rationale = {
        "label": "BENIGN",
        "target": target,
        "method": "fixed_seed_sample_of_the_cleaned_view",
        "availableSourceDistribution": _distribution(benign_frame, "source"),
        "sampledSourceDistribution": _distribution(benign_sample, "source"),
        "syntheticRowsCreated": 0,
        "duplicateRowsCreated": 0,
    }
    binary_view = (
        pd.concat([benign_sample, phishing_sample], ignore_index=True)
        .sample(frac=1, random_state=seed)
        .reset_index(drop=True)
    )
    binary_view["binary_label"] = binary_view["label"].map(BINARY_LABEL_MAPPING)
    binary_view.to_csv(views_dir / "binary_domain_only.csv", index=False, lineterminator="\n")

    parts = _apply_shared_split(binary_view, ratios, seed)
    splits_root = project_path("data/splits/v1.3.0")
    directory = splits_root / "binary"
    directory.mkdir(parents=True, exist_ok=True)
    for name, frame in zip(("train", "validation", "test"), parts):
        frame.to_csv(directory / f"{name}.csv", index=False, lineterminator="\n")
    train, validation, test = parts

    manifest_path = splits_root / "test_manifest_v1.3.0.json"
    candidate = build_test_manifest(DATASET_VERSION, {"binary": test}, seed)
    candidate["labelSpace"] = BINARY_LABEL_MAPPING
    candidate["label"] = "binary phishing frozen test"
    verify_test_manifest_candidate(manifest_path, candidate)
    manifest = seal_test_manifest(manifest_path, candidate)

    snapshots = load_snapshot_catalog(raw_root)
    metadata: dict[str, Any] = {
        "metadataSchemaVersion": 4,
        "datasetVersion": DATASET_VERSION,
        "status": "OFFICIAL_SOURCE_SET",
        "task": "binary_phishing",
        "labelMapping": BINARY_LABEL_MAPPING,
        "labelSpace": ["BENIGN", "PHISHING"],
        "malwareHandling": {
            "role": "handled by the Threat Intelligence layer, not by the binary ML label space",
            "excludedRawRows": int(len(malware_rows)),
            "excludedSources": sorted(set(malware_rows["source"].astype(str))),
            "threatIntelligenceProviders": ["URLHAUS", "THREATFOX"],
        },
        "buildDate": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rawClassDistribution": _distribution(binary_raw),
        "rawSourceDistribution": _distribution(binary_raw, "source"),
        "selectedRawClassDistribution": _distribution(raw),
        "selectedRawSourceDistribution": _distribution(raw, "source"),
        "classDistribution": _distribution(clean),
        "sourceDistribution": _distribution(clean, "source"),
        "uniqueUrlCount": int(clean["normalized_url"].nunique()),
        "numberOfUniqueDomains": int(clean["registrable_domain"].nunique()),
        "numberOfRows": int(len(clean)),
        "cleaningStats": cleaning.to_dict(),
        "numberOfDomainLabelConflicts": domain_conflicts,
        "crossSourceConflictAudit": conflict_audit,
        "openphishAccumulation": openphish_accumulated.to_dict(),
        "sampling": {"benign": benign_rationale, "phishing": phishing_rationale},
        "viewDistribution": _distribution(binary_view),
        "viewSourceDistribution": _distribution(binary_view, "source"),
        "splits": {
            "trainSize": int(len(train)),
            "validationSize": int(len(validation)),
            "testSize": int(len(test)),
            "trainDistribution": _distribution(train),
            "validationDistribution": _distribution(validation),
            "testDistribution": _distribution(test),
            "trainSourceDistribution": _distribution(train, "source"),
            "testSourceDistribution": _distribution(test, "source"),
            "uniqueDomains": {
                "train": int(train["registrable_domain"].nunique()),
                "validation": int(validation["registrable_domain"].nunique()),
                "test": int(test["registrable_domain"].nunique()),
            },
            "domainLeakage": 0,
        },
        "splitSeed": seed,
        "splitMethod": ratios_config["method"],
        "testManifest": manifest,
        "testManifestSHA256": _sha256_file(manifest_path),
        "snapshots": snapshots,
        "sourcePolicyVersion": config.get("sources", {}).get("policy_version"),
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "notes": (
            "Phishing.Database and other community feeds may contain false positives; records are "
            "treated as community reports, not ground truth, and are audited for cross-source conflicts."
        ),
    }
    metadata_path = processing_dir / "dataset_metadata.json"
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return metadata
