"""Threat Intelligence source-overlap audit.

The binary dataset's PHISHING rows come from phishing feeds, while the Threat
Intelligence layer indexes malware feeds. If phishing rows hit the malware
intelligence almost universally, UGDM could learn a near-constant rule
(`threat_intel_hit -> dangerous`) instead of a real decision function.

This audit quantifies that risk before any model is trained.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from src.data.hosttype import classify_host_type
from src.ugdm.threat_intel_snapshot import FrozenThreatIntelSnapshot


@dataclass
class OverlapAudit:
    """Hit rates for one labelled slice of the binary dataset."""

    label: str
    rows: int
    hits: int
    hit_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "rows": self.rows, "hits": self.hits, "hitRate": self.hit_rate}


def _host_from_row(hostname: str, registrable_domain: str) -> tuple[str, str]:
    return str(hostname), str(registrable_domain)


def audit_overlap(
    frame: pd.DataFrame,
    snapshot: FrozenThreatIntelSnapshot,
) -> dict[str, Any]:
    """Compute hit rate by label, by source and by host type."""

    if "hostname" not in frame.columns:
        raise ValueError("Overlap audit requires a hostname column")

    hits = []
    for hostname, registrable_domain in zip(
        frame["hostname"].astype(str), frame["registrable_domain"].astype(str)
    ):
        host, domain = _host_from_row(hostname, registrable_domain)
        hits.append(snapshot.contains(host) or snapshot.contains(domain))
    working = frame.assign(threat_intel_hit=hits)

    by_label = [
        OverlapAudit(
            label=str(label),
            rows=int(len(group)),
            hits=int(group["threat_intel_hit"].sum()),
            hit_rate=float(group["threat_intel_hit"].mean()),
        )
        for label, group in working.groupby("label", sort=True)
    ]
    by_source = [
        OverlapAudit(
            label=str(source),
            rows=int(len(group)),
            hits=int(group["threat_intel_hit"].sum()),
            hit_rate=float(group["threat_intel_hit"].mean()),
        )
        for source, group in working.groupby("source", sort=True)
    ]
    host_types = working["registrable_domain"].map(classify_host_type)
    by_host_type = [
        OverlapAudit(
            label=str(host_type),
            rows=int(len(group)),
            hits=int(group["threat_intel_hit"].sum()),
            hit_rate=float(group["threat_intel_hit"].mean()),
        )
        for host_type, group in working.groupby(host_types, sort=True)
    ]

    phishing = next((item for item in by_label if item.label == "PHISHING"), None)
    benign = next((item for item in by_label if item.label == "BENIGN"), None)
    separation = (
        (phishing.hit_rate - benign.hit_rate) if phishing is not None and benign is not None else None
    )
    return {
        "byLabel": [item.to_dict() for item in by_label],
        "bySource": [item.to_dict() for item in by_source],
        "byHostType": [item.to_dict() for item in by_host_type],
        "phishingMinusBenignHitRate": separation,
        "interpretation": (
            "A large hit-rate separation means the Threat Intelligence features alone nearly "
            "separate the labels, so the no-ThreatIntel ablation is required to show what the "
            "model contributes beyond that rule."
        ),
    }


def write_overlap_audit(payload: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
