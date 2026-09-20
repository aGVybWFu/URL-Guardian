"""dataset-v1.2.0 construction: host-type audit plus Natural and Artifact-Controlled regimes.

Design goals:

* Never modify `dataset-v1.1.0`. Everything is written under new versioned paths.
* Quantify the MALWARE IP-host artifact and reduce it with real records only.
* Provide two documented sampling regimes:
  - NATURAL: keeps the source host-type distribution.
  - ARTIFACT_CONTROLLED: keeps every confirmed domain-hosted malware record and
    downsamples IP-hosted malware so that `host_type` stops being a near-perfect
    MALWARE predictor.
* Never create synthetic rows and never duplicate rows to reach a target.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.data.cleaner import clean_dataset
from src.data.hosttype import (
    HOST_TYPES,
    artifact_controlled_malware_sample,
    classify_host_type,
    host_type_counts,
    host_type_distribution,
)
from src.data.loader import load_raw_dataset
from src.data.manifest import build_test_manifest, seal_test_manifest, verify_test_manifest_candidate
from src.data.snapshot import load_snapshot_catalog
from src.data.splitter import assert_no_domain_leakage, domain_aware_split
from src.data.views import create_domain_only_view, sample_per_class, write_domain_label_conflicts
from src.evaluation.dataset_bias import audit_dataset_views
from src.utils.config import load_config, project_path

LABELS = {"BENIGN", "PHISHING", "MALWARE"}
REGIMES = ("natural", "artifact_controlled")
DATASET_VERSION = "dataset-v1.2.0"


def _distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {str(key): int(value) for key, value in frame["label"].value_counts().sort_index().items()}


def _source_distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {str(key): int(value) for key, value in frame["source"].value_counts().sort_index().items()}


def preselect_large_domain_sources(
    raw: pd.DataFrame, target: int, seed: int, multiplier: int
) -> pd.DataFrame:
    """Deterministic per-source cap for very large domain-only sources."""

    cap = target * multiplier
    parts: list[pd.DataFrame] = []
    for source, group in raw.groupby("source", sort=True, dropna=False):
        if source in {"tranco", "cert_polska"} and len(group) > cap:
            group = group.sample(n=cap, random_state=seed)
        parts.append(group)
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def audit_malware_ip_artifact(raw: pd.DataFrame, cleaned: pd.DataFrame, view: pd.DataFrame) -> dict[str, Any]:
    """Quantify where the IP-host share comes from, stage by stage."""

    def stage(frame: pd.DataFrame, name: str) -> dict[str, Any]:
        malware = frame[frame["label"].astype(str) == "MALWARE"]
        if "registrable_domain" in malware.columns:
            hosts = malware["registrable_domain"].astype(str)
        else:
            hosts = (
                malware["url"]
                .astype(str)
                .str.extract(r"^[a-zA-Z]+://([^/?#]+)")[0]
                .str.replace(r":\d+$", "", regex=True)
            )
        types = hosts.map(classify_host_type)
        counts = {host_type: int((types == host_type).sum()) for host_type in HOST_TYPES}
        unique = {host_type: int(hosts[types == host_type].nunique()) for host_type in HOST_TYPES}
        total = sum(counts.values())
        return {
            "stage": name,
            "rows": int(len(malware)),
            "hostTypeCounts": counts,
            "hostTypeShare": {
                host_type: (counts[host_type] / total if total else 0.0) for host_type in HOST_TYPES
            },
            "uniqueHostsByType": unique,
        }

    stages = [
        stage(raw, "raw_union"),
        stage(cleaned, "after_cleaning"),
        stage(view, "after_domain_only_dedup"),
    ]
    return {
        "stages": stages,
        "conclusion": (
            "The official URLhaus recent export is itself IP-dominated. Registrable-domain "
            "deduplication then removes a larger share of domain-hosted rows than of IP-hosted "
            "rows, which further increases the IP share inside DOMAIN_ONLY."
        ),
    }


def _regime_frame(
    view: pd.DataFrame,
    regime: str,
    target: int,
    seed: int,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Apply the sampling regime to the DOMAIN_ONLY view."""

    malware = view[view["label"].astype(str) == "MALWARE"]
    rationale: dict[str, Any] = {
        "regime": regime,
        "targetPerClass": target,
        "seed": seed,
        "syntheticRowsCreated": 0,
        "duplicateRowsCreated": 0,
    }
    if regime == "natural":
        sampled = sample_per_class(view, target, seed)
        rationale.update(
            {
                "method": "fixed_seed_per_class_sample_of_the_cleaned_view",
                "malwareHostTypeCounts": host_type_counts(malware),
                "malwareHostTypeShare": host_type_distribution(malware),
                "note": "Source host-type distribution is preserved without intervention.",
            }
        )
        return sampled, rationale

    other = view[view["label"].astype(str) != "MALWARE"]
    sampled_other = sample_per_class(other, target, seed)
    controlled, control_rationale = artifact_controlled_malware_sample(
        pd.concat([sampled_other, malware], ignore_index=True), seed
    )
    rationale.update(
        {
            "method": "keep_all_domain_hosts_and_cap_ip_hosts_at_domain_count",
            "malwareControl": control_rationale,
            "malwareHostTypeCounts": host_type_counts(
                controlled[controlled["label"].astype(str) == "MALWARE"]
            ),
            "malwareHostTypeShare": host_type_distribution(
                controlled[controlled["label"].astype(str) == "MALWARE"]
            ),
            "note": (
                "Benign and phishing are sampled identically to the natural regime. MALWARE keeps "
                "every confirmed domain-hosted record and downsamples IP-hosted records so that "
                "host type alone cannot drive MALWARE recall."
            ),
        }
    )
    return controlled, rationale


def _apply_shared_split(
    frame: pd.DataFrame, ratios: tuple[float, float, float], seed: int
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    parts = domain_aware_split(frame, *ratios, seed)
    assert_no_domain_leakage(*parts)
    return parts


def _save_splits(parts: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, frame in zip(("train", "validation", "test"), parts):
        frame.to_csv(directory / f"{name}.csv", index=False, lineterminator="\n")


def build_dataset_v12(config_path: str | Path | None = None) -> dict[str, Any]:
    """Build dataset-v1.2.0 with both sampling regimes and frozen manifests."""

    config = load_config(config_path)
    seed = int(config["random_seed"])
    target = int(config.get("dataset", {}).get("target_per_class", 20_000))
    multiplier = int(config.get("dataset", {}).get("preselection_multiplier", 2))
    ratios_config = config["split"]
    ratios = (
        float(ratios_config["train_ratio"]),
        float(ratios_config["validation_ratio"]),
        float(ratios_config["test_ratio"]),
    )
    raw_root = project_path(config["paths"]["raw"])
    raw_all = load_raw_dataset(raw_root)
    if raw_all.empty:
        raise RuntimeError("No formal raw data found for dataset-v1.2.0")

    raw_labels = set(raw_all["label"].dropna().astype(str).str.upper())
    missing = sorted(LABELS.difference(raw_labels))
    if missing:
        raise RuntimeError(f"dataset-v1.2.0 requires all three labels; missing: {missing}")

    raw = preselect_large_domain_sources(raw_all, target, seed, multiplier)
    conflicts_path = project_path("reports/v1.2.0/conflicts.csv")
    clean, cleaning = clean_dataset(raw, conflicts_path)
    if clean.empty:
        raise RuntimeError("No usable rows remain after cleaning for dataset-v1.2.0")

    processing_dir = project_path("data/processed/v1.2.0")
    processing_dir.mkdir(parents=True, exist_ok=True)
    clean.to_csv(processing_dir / "cleaned_dataset.csv", index=False, lineterminator="\n")
    domain_conflict_count = write_domain_label_conflicts(
        clean, project_path("reports/v1.2.0/domain_label_conflicts.csv")
    )

    domain_only_full = create_domain_only_view(
        clean, project_path("reports/v1.2.0/domain_only_conflicts.csv")
    )
    domain_only_full["host_type"] = domain_only_full["registrable_domain"].map(classify_host_type)
    views_dir = processing_dir / "views"
    views_dir.mkdir(parents=True, exist_ok=True)
    domain_only_full.to_csv(
        views_dir / "domain_only_full.csv", index=False, lineterminator="\n"
    )

    artifact_audit = audit_malware_ip_artifact(raw, clean, domain_only_full)

    splits_root = project_path("data/splits/v1.2.0")
    regimes: dict[str, Any] = {}
    test_frames: dict[str, pd.DataFrame] = {}
    for regime in REGIMES:
        frame, rationale = _regime_frame(domain_only_full, regime, target, seed)
        frame.to_csv(views_dir / f"{regime}_domain_only.csv", index=False, lineterminator="\n")
        parts = _apply_shared_split(frame, ratios, seed)
        directory = splits_root / regime
        _save_splits(parts, directory)
        train, validation, test = parts
        test_frames[regime] = test
        regimes[regime] = {
            "samplingRationale": rationale,
            "viewDistribution": _distribution(frame),
            "hostTypeCounts": host_type_counts(frame),
            "hostTypeShare": host_type_distribution(frame),
            "splits": {
                "trainSize": int(len(train)),
                "validationSize": int(len(validation)),
                "testSize": int(len(test)),
                "trainDistribution": _distribution(train),
                "validationDistribution": _distribution(validation),
                "testDistribution": _distribution(test),
                "uniqueDomains": {
                    "train": int(train["registrable_domain"].nunique()),
                    "validation": int(validation["registrable_domain"].nunique()),
                    "test": int(test["registrable_domain"].nunique()),
                },
                "domainLeakage": 0,
                "testHostTypeCounts": host_type_counts(test),
                "testHostTypeShare": host_type_distribution(test),
            },
        }

    primary = "artifact_controlled"
    manifest_path = splits_root / "test_manifest_v1.2.0.json"
    candidate = build_test_manifest(
        DATASET_VERSION,
        {regime: test_frames[regime] for regime in REGIMES if regime == primary},
        seed,
    )
    for regime in REGIMES:
        if regime != primary:
            entry = build_test_manifest(DATASET_VERSION, {regime: test_frames[regime]}, seed)["views"]
            candidate["views"].update(entry)
    combined = "\n".join(
        f"{view}:{entry['sha256']}" for view, entry in sorted(candidate["views"].items())
    )
    candidate["combinedTestSetSha256"] = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    candidate["primaryRegime"] = primary
    verify_test_manifest_candidate(manifest_path, candidate)
    manifest = seal_test_manifest(manifest_path, candidate)

    audit_dir = project_path("reports/v1.2.0/dataset_bias")
    bias = audit_dataset_views(
        {
            regime: pd.read_csv(views_dir / f"{regime}_domain_only.csv", dtype=str, low_memory=False)
            for regime in REGIMES
        },
        audit_dir,
    )

    snapshots = load_snapshot_catalog(raw_root)
    metadata: dict[str, Any] = {
        "metadataSchemaVersion": 3,
        "datasetVersion": DATASET_VERSION,
        "status": "OFFICIAL_SOURCE_SET" if not missing else "INCOMPLETE_SOURCE_SET",
        "buildDate": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "primaryRegime": primary,
        "regimes": list(REGIMES),
        "rawClassDistribution": _distribution(raw_all),
        "rawSourceDistribution": _source_distribution(raw_all),
        "selectedRawClassDistribution": _distribution(raw),
        "selectedRawSourceDistribution": _source_distribution(raw),
        "preselection": {
            "method": "fixed_seed_source_cap",
            "seed": seed,
            "capForLargeDomainSources": target * multiplier,
            "cappedSources": ["cert_polska", "tranco"],
        },
        "classDistribution": _distribution(clean),
        "sourceDistribution": _source_distribution(clean),
        "uniqueUrlCount": int(clean["normalized_url"].nunique()),
        "numberOfUniqueDomains": int(clean["registrable_domain"].nunique()),
        "numberOfRows": int(len(clean)),
        "cleaningStats": cleaning.to_dict(),
        "numberOfDomainLabelConflicts": domain_conflict_count,
        "malwareIpArtifactAudit": artifact_audit,
        "regimeDetails": regimes,
        "splitSeed": seed,
        "splitMethod": ratios_config["method"],
        "biasAudit": bias,
        "snapshots": snapshots,
        "testManifest": manifest,
        "testManifestSHA256": _sha256_file(manifest_path),
        "viewEligibility": {"domain_only": True, "full_url": False},
        "officialExperimentEligible": True,
        "hostTypeUsage": {
            "role": "audit, stratification and subgroup analysis only",
            "isModelFeature": False,
        },
        "sourcePolicyVersion": config.get("sources", {}).get("policy_version"),
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
        "labelMapping": {"BENIGN": 0, "PHISHING": 1, "MALWARE": 2},
    }
    metadata_path = processing_dir / "dataset_metadata.json"
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return metadata


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
