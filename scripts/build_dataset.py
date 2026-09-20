from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.cleaner import clean_dataset
from src.data.loader import load_raw_dataset
from src.data.manifest import build_test_manifest, seal_test_manifest, verify_test_manifest_candidate
from src.data.snapshot import load_snapshot_catalog
from src.data.splitter import assert_no_domain_leakage, domain_aware_split, save_splits
from src.data.views import (
    create_domain_only_view,
    create_full_url_view,
    sample_per_class,
    write_domain_label_conflicts,
)
from src.evaluation.dataset_bias import audit_dataset_views
from src.utils.config import load_config, project_path
from src.utils.logging import configure_logging, get_logger
from src.utils.seed import set_seed

LOGGER = get_logger(__name__)
LABELS = {"BENIGN", "PHISHING", "MALWARE"}


def _distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {str(key): int(value) for key, value in frame["label"].value_counts().sort_index().items()}


def _write_metadata(path: Path, metadata: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    history = path.parent / "metadata"
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        previous_version = str(previous.get("datasetVersion", "unknown"))
        history.mkdir(parents=True, exist_ok=True)
        archived = history / f"{previous_version}.json"
        if not archived.exists():
            archived.write_text(json.dumps(previous, ensure_ascii=False, indent=2), encoding="utf-8")
    version = str(metadata.get("datasetVersion", "unknown"))
    history.mkdir(parents=True, exist_ok=True)
    (history / f"{version}.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def _preselect_large_domain_sources(raw: pd.DataFrame, target: int, seed: int, multiplier: int) -> pd.DataFrame:
    cap = target * multiplier
    parts: list[pd.DataFrame] = []
    for source, group in raw.groupby("source", sort=True, dropna=False):
        if source in {"tranco", "cert_polska"} and len(group) > cap:
            group = group.sample(n=cap, random_state=seed)
        parts.append(group)
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def _apply_shared_split(
    views: dict[str, pd.DataFrame], ratios: tuple[float, float, float], seed: int
) -> dict[str, tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]]:
    combined = pd.concat(views.values(), ignore_index=True)
    combined_parts = domain_aware_split(combined, *ratios, seed)
    domain_sets = [set(part["registrable_domain"]) for part in combined_parts]
    output: dict[str, tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]] = {}
    for name, frame in views.items():
        parts = tuple(
            frame[frame["registrable_domain"].isin(domains)].reset_index(drop=True)
            for domains in domain_sets
        )
        assert_no_domain_leakage(*parts)
        output[name] = parts  # type: ignore[assignment]
    return output


def build_dataset(config_path: str | Path | None = None) -> dict[str, object]:
    configure_logging()
    config = load_config(config_path)
    seed = int(config["random_seed"])
    set_seed(seed)
    raw_root = project_path(config["paths"]["raw"])
    raw_all = load_raw_dataset(raw_root)
    if raw_all.empty:
        raise RuntimeError("No formal raw data found. Acquire the approved official source snapshots first.")
    raw_labels = set(raw_all["label"].dropna().astype(str).str.upper())
    missing_labels = sorted(LABELS.difference(raw_labels))
    if missing_labels:
        readiness = {
            "datasetVersion": str(config["project"]["dataset_version"]),
            "status": "INCOMPLETE_SOURCE_SET",
            "buildDate": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "rawClassDistribution": _distribution(raw_all),
            "rawSourceDistribution": {
                str(key): int(value) for key, value in raw_all["source"].value_counts().sort_index().items()
            },
            "missingLabels": missing_labels,
            "snapshots": load_snapshot_catalog(raw_root),
            "officialExperimentEligible": False,
        }
        metadata_path = project_path(config["paths"]["dataset_metadata"])
        _write_metadata(metadata_path, readiness)
        LOGGER.warning("Formal build deferred because labels are missing: %s", ", ".join(missing_labels))
        return readiness
    target = int(config.get("dataset", {}).get("target_per_class", 20_000))
    multiplier = int(config.get("dataset", {}).get("preselection_multiplier", 2))
    raw = _preselect_large_domain_sources(raw_all, target, seed, multiplier)
    clean, cleaning = clean_dataset(raw, project_path(config["paths"]["conflicts"]))
    if clean.empty:
        raise RuntimeError("No usable rows remain after cleaning")

    processed_path = project_path(config["paths"]["processed"])
    processed_dir = processed_path.parent
    processed_dir.mkdir(parents=True, exist_ok=True)
    clean.to_csv(processed_dir / "full_cleaned_dataset.csv", index=False)
    clean.to_csv(processed_path, index=False)
    domain_conflicts_path = project_path(
        config["paths"].get("domain_conflicts", "reports/domain_label_conflicts.csv")
    )
    domain_conflict_count = write_domain_label_conflicts(clean, domain_conflicts_path)

    experiment_mode = str(config.get("training", {}).get("experiment_mode", "FIXTURE_VERIFICATION"))
    domain_only_full = create_domain_only_view(
        clean, project_path(config["paths"].get("domain_only_conflicts", "reports/domain_only_conflicts.csv"))
    )
    fixture_sources = None
    if experiment_mode == "FIXTURE_VERIFICATION":
        fixture_sources = {
            label: set(clean.loc[clean["label"].eq(label), "source"].astype(str)) for label in LABELS
        }
    full_url_full = create_full_url_view(clean, fixture_sources)
    views_dir = processed_dir / "views"
    views_dir.mkdir(parents=True, exist_ok=True)
    domain_only_full.to_csv(views_dir / "domain_only_full.csv", index=False)
    full_url_full.to_csv(views_dir / "full_url_full.csv", index=False)
    views = {
        "domain_only": sample_per_class(domain_only_full, target, seed),
        "full_url": sample_per_class(full_url_full, target, seed),
    }
    for name, frame in views.items():
        frame.to_csv(views_dir / f"{name}.csv", index=False)

    audit_dir = project_path(config["paths"].get("dataset_bias", "reports/dataset_bias"))
    bias = audit_dataset_views(views, audit_dir)
    split_config = config["split"]
    ratios = (
        float(split_config["train_ratio"]),
        float(split_config["validation_ratio"]),
        float(split_config["test_ratio"]),
    )
    source_policy = config.get("sources", {})
    bias_reviewed = bool(source_policy.get("bias_reviewed", False)) or experiment_mode == "FIXTURE_VERIFICATION"
    labels_ready = all(set(frame["label"].unique()) == LABELS for frame in views.values())
    can_split = labels_ready and bias_reviewed
    split_metadata: dict[str, object] = {}
    test_manifest: dict[str, object] | None = None
    if can_split:
        view_parts = _apply_shared_split(views, ratios, seed)
        for name, parts in view_parts.items():
            for split_name, part in zip(("train", "validation", "test"), parts):
                if set(part["label"].unique()) != LABELS:
                    raise RuntimeError(f"{name} {split_name} split does not contain all three labels")
        splits_root = project_path(config["paths"]["splits"])
        manifest_path = splits_root / "test_manifest.json"
        test_frames = {name: parts[2] for name, parts in view_parts.items()}
        candidate_manifest = build_test_manifest(
            str(config["project"]["dataset_version"]), test_frames, seed
        )
        verify_test_manifest_candidate(manifest_path, candidate_manifest)
        for name, parts in view_parts.items():
            directory = splits_root / name
            save_splits(parts, directory)
            train, validation, test = parts
            split_metadata[name] = {
                "trainSize": len(train),
                "validationSize": len(validation),
                "testSize": len(test),
                "trainDistribution": _distribution(train),
                "validationDistribution": _distribution(validation),
                "testDistribution": _distribution(test),
                "uniqueDomains": {
                    "train": int(train["registrable_domain"].nunique()),
                    "validation": int(validation["registrable_domain"].nunique()),
                    "test": int(test["registrable_domain"].nunique()),
                },
                "domainLeakage": 0,
            }
        test_manifest = seal_test_manifest(manifest_path, candidate_manifest)
    else:
        reason = "bias review is not approved" if labels_ready else "both views do not contain all three labels"
        LOGGER.warning("Formal splits were not created because %s", reason)

    digest = hashlib.sha256(processed_path.read_bytes()).hexdigest()
    snapshots = load_snapshot_catalog(raw_root)
    snapshot_sources = {
        entry.get("source")
        for snapshot in snapshots
        for entry in snapshot.get("sources", [])
    }
    required_sources = set(source_policy.get("required", ["tranco", "openphish", "cert_polska", "urlhaus"]))
    source_ready = required_sources.issubset(snapshot_sources)
    policy_ready = (
        experiment_mode == "OFFICIAL_EXPERIMENT"
        and bool(source_policy.get("official_run_approved", False))
        and bias_reviewed
        and source_ready
    )
    domain_only_eligible = bool(can_split and policy_ready)
    full_url_benign = views["full_url"][views["full_url"]["label"].eq("BENIGN")]
    full_url_adequate = (
        len(full_url_benign) >= int(config.get("dataset", {}).get("full_url_min_benign_records", 20_000))
        and full_url_benign["registrable_domain"].nunique()
        >= int(config.get("dataset", {}).get("full_url_min_benign_domains", 4_000))
    )
    full_url_eligible = bool(domain_only_eligible and full_url_adequate)
    official_eligible = domain_only_eligible
    metadata: dict[str, object] = {
        "datasetVersion": str(config["project"]["dataset_version"]),
        "dataSha256": digest,
        "snapshotIds": [item.get("snapshot_id") for item in snapshots],
        "snapshots": snapshots,
        "buildDate": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rawClassDistribution": _distribution(raw_all),
        "rawSourceDistribution": {
            str(key): int(value) for key, value in raw_all["source"].value_counts().sort_index().items()
        },
        "selectedRawClassDistribution": _distribution(raw),
        "selectedRawSourceDistribution": {
            str(key): int(value) for key, value in raw["source"].value_counts().sort_index().items()
        },
        "preselection": {
            "method": "fixed_seed_source_cap",
            "seed": seed,
            "capForLargeDomainSources": target * multiplier,
            "cappedSources": ["cert_polska", "tranco"],
        },
        "classDistribution": _distribution(clean),
        "sourceDistribution": {
            str(key): int(value) for key, value in clean["source"].value_counts().sort_index().items()
        },
        "uniqueUrlCount": int(clean["normalized_url"].nunique()),
        "numberOfUniqueDomains": int(clean["registrable_domain"].nunique()),
        "numberOfRows": len(clean),
        "numberOfRemovedDuplicates": cleaning.removed_exact_duplicates + cleaning.removed_normalized_duplicates,
        "numberOfRemovedInvalidRows": cleaning.removed_empty + cleaning.removed_invalid_label + cleaning.removed_invalid_urls,
        "numberOfConflicts": cleaning.removed_conflicts,
        "numberOfDomainLabelConflicts": domain_conflict_count,
        "cleaningStats": cleaning.to_dict(),
        "viewDistributions": {name: _distribution(frame) for name, frame in views.items()},
        "splitSeed": seed,
        "randomSeed": seed,
        "splitMethod": split_config["method"],
        "domainLeakage": 0 if can_split else None,
        "splits": split_metadata,
        "testManifest": test_manifest,
        "biasAudit": bias,
        "sourcePolicyVersion": source_policy.get("policy_version"),
        "requiredSnapshotSources": sorted(required_sources),
        "missingSnapshotSources": sorted(required_sources.difference(snapshot_sources)),
        "biasReviewed": bias_reviewed,
        "experimentMode": experiment_mode,
        "viewEligibility": {
            "domain_only": domain_only_eligible,
            "full_url": full_url_eligible,
        },
        "fullUrlAdequacy": {
            "eligible": full_url_adequate,
            "benignRecords": len(full_url_benign),
            "benignDomains": int(full_url_benign["registrable_domain"].nunique()),
            "minimumRecords": int(config.get("dataset", {}).get("full_url_min_benign_records", 20_000)),
            "minimumDomains": int(config.get("dataset", {}).get("full_url_min_benign_domains", 4_000)),
        },
        "officialExperimentEligible": official_eligible,
    }
    if can_split:
        legacy = split_metadata["domain_only"]
        metadata.update(legacy)
    metadata_path = project_path(config["paths"]["dataset_metadata"])
    _write_metadata(metadata_path, metadata)
    LOGGER.info("Built cleaned dataset with %d rows and %d unique domains", len(clean), clean["registrable_domain"].nunique())
    return metadata


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(description="Build both URL Guardian dataset views and shared domain splits")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(build_dataset(args.config), ensure_ascii=False, indent=2))
    except (OSError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
