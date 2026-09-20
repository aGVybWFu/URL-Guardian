"""Host-type classification and malware host-type auditing.

`host_type` describes whether a frozen row is addressed by a domain name or by
a literal IP address. It is a dataset property used for auditing, stratification
and subgroup analysis. It is never a model input: `source`, provider identity and
label-derived values remain forbidden as features.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

import pandas as pd

DOMAIN = "DOMAIN"
IPV4 = "IPV4"
IPV6 = "IPV6"
HOST_TYPES = (DOMAIN, IPV4, IPV6)


def classify_host_type(value: object) -> str:
    """Classify a host or registrable-domain string as DOMAIN, IPV4 or IPV6."""

    text = str(value).strip().strip("[]")
    if not text:
        return DOMAIN
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return DOMAIN
    return IPV4 if address.version == 4 else IPV6


def host_type_series(values: Iterable[object]) -> pd.Series:
    return pd.Series([classify_host_type(value) for value in values], dtype="string")


def host_type_counts(frame: pd.DataFrame, column: str = "registrable_domain") -> dict[str, int]:
    """Count DOMAIN / IPV4 / IPV6 rows, always returning every key."""

    counts = frame[column].map(classify_host_type).value_counts()
    return {host_type: int(counts.get(host_type, 0)) for host_type in HOST_TYPES}


def host_type_distribution(frame: pd.DataFrame, column: str = "registrable_domain") -> dict[str, float]:
    """Share of each host type, always returning every key."""

    counts = host_type_counts(frame, column)
    total = sum(counts.values())
    if total == 0:
        return {host_type: 0.0 for host_type in HOST_TYPES}
    return {host_type: counts[host_type] / total for host_type in HOST_TYPES}


def audit_malware_host_types(frame: pd.DataFrame, label_column: str = "label") -> dict[str, object]:
    """Summarise host-type composition for every label plus the MALWARE split."""

    report: dict[str, object] = {}
    for label in sorted(frame[label_column].astype(str).unique()):
        subset = frame[frame[label_column].astype(str) == label]
        report[label] = {
            "rows": int(len(subset)),
            "hostTypeCounts": host_type_counts(subset),
            "hostTypeShare": host_type_distribution(subset),
            "uniqueRegistrableDomains": int(subset["registrable_domain"].nunique()),
        }
    return report


def artifact_controlled_malware_sample(
    frame: pd.DataFrame,
    seed: int,
    *,
    label: str = "MALWARE",
    column: str = "registrable_domain",
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Downsample IP-hosted malware so that host type stops dominating the label.

    All confirmed domain-hosted malware records are kept. IP-hosted malware is
    kept as a real class but downsampled to the same count, so `host_type` alone
    can no longer support a high MALWARE recall. No synthetic rows, no
    duplication, and no record is invented: only real confirmed source records
    are used, and the removed IP rows stay available in the natural dataset.
    """

    malware = frame[frame["label"].astype(str) == label]
    host_types = malware[column].map(classify_host_type)
    domain_rows = malware[host_types == DOMAIN]
    ip_rows = malware[host_types != DOMAIN]
    target_ip = min(len(ip_rows), len(domain_rows))
    sampled_ip = (
        ip_rows.sample(n=target_ip, random_state=seed) if target_ip < len(ip_rows) else ip_rows
    )
    kept = pd.concat([domain_rows, sampled_ip], ignore_index=True)
    kept = kept.sample(frac=1, random_state=seed).reset_index(drop=True)
    other = frame[frame["label"].astype(str) != label]
    combined = pd.concat([other, kept], ignore_index=True).reset_index(drop=True)
    rationale = {
        "label": label,
        "method": "keep_all_domain_hosts_and_cap_ip_hosts_at_domain_count",
        "domainHostRecords": int(len(domain_rows)),
        "ipHostRecordsAvailable": int(len(ip_rows)),
        "ipHostRecordsKept": int(len(sampled_ip)),
        "ipHostRecordsDropped": int(len(ip_rows) - len(sampled_ip)),
        "resultingIpShare": (
            float(len(sampled_ip) / len(kept)) if len(kept) else None
        ),
        "syntheticRowsCreated": 0,
        "duplicateRowsCreated": 0,
        "note": (
            "IP-hosted malware is a real threat class and is retained; it is only "
            "downsampled so that host type is not a near-perfect predictor of MALWARE. "
            "Dropped IP rows remain in the natural dataset."
        ),
    }
    return combined, rationale
