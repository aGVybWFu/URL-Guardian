"""Error analysis, IP subgroup analysis and source-bias analysis for URLBERT.

All outputs are derived from the single official Test prediction file. Subgroup
tables are research diagnostics only: they never redefine the frozen Test Set.
Domain strings are exported as hashes plus a redacted form rather than raw
malicious hostnames.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from src.evaluation.metrics import LABEL_NAMES
from src.models.urlbert.config import load_urlbert_config
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def _is_ip_host(value: str) -> bool:
    text = value.strip().strip("[]")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _hash_domain(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _redact_domain(value: str) -> str:
    if _is_ip_host(value):
        return "IP-address"
    parts = value.rsplit(".", 1)
    suffix = parts[-1] if parts else ""
    return f"***.{suffix}" if suffix else "***"


def _subgroup_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, Any]:
    present = sorted({int(value) for value in labels})
    metrics: dict[str, Any] = {
        "sampleCount": int(labels.size),
        "presentClasses": ",".join(LABEL_NAMES[index] for index in present),
        "accuracy": float(accuracy_score(labels, predictions)) if labels.size else None,
        "macroF1": float(f1_score(labels, predictions, labels=present, average="macro", zero_division=0))
        if labels.size
        else None,
        "macroPrecision": float(
            precision_score(labels, predictions, labels=present, average="macro", zero_division=0)
        )
        if labels.size
        else None,
        "macroRecall": float(
            recall_score(labels, predictions, labels=present, average="macro", zero_division=0)
        )
        if labels.size
        else None,
    }
    for index, name in enumerate(LABEL_NAMES):
        mask = labels == index
        metrics[f"{name.lower()}Support"] = int(mask.sum())
        metrics[f"{name.lower()}Recall"] = (
            float((predictions[mask] == index).mean()) if mask.any() else None
        )
    benign = labels == 0
    malicious = labels != 0
    metrics["benignFpr"] = float((predictions[benign] != 0).mean()) if benign.any() else None
    metrics["maliciousFnr"] = float((predictions[malicious] == 0).mean()) if malicious.any() else None
    return metrics


def _error_rows(frame: pd.DataFrame, condition: pd.Series, error_type: str) -> pd.DataFrame:
    selected = frame[condition]
    return pd.DataFrame(
        {
            "rowId": selected["rowId"],
            "errorType": error_type,
            "trueLabel": selected["label"],
            "predictedLabel": selected["predicted"],
            "source": selected["source"],
            "domainHash": selected["registrableDomain"].map(_hash_domain),
            "redactedDomain": selected["registrableDomain"].map(_redact_domain),
            "domainLength": selected["registrableDomain"].str.len(),
            "isIpHost": selected["registrableDomain"].map(_is_ip_host),
            "probabilityBenign": selected["probabilityBenign"],
            "probabilityPhishing": selected["probabilityPhishing"],
            "probabilityMalware": selected["probabilityMalware"],
        }
    )


def run_analysis(config_path: str | Path | None = None) -> dict[str, Any]:
    """Generate error, IP-subgroup and source-bias reports for the URLBERT Test run."""

    configure_logging()
    config = load_urlbert_config(config_path)
    predictions_path = config.path("metrics") / "test_predictions.csv"
    if not predictions_path.exists():
        raise FileNotFoundError("Run the official URLBERT Test evaluation before the analysis")
    frame = pd.read_csv(predictions_path, dtype=str)
    frame["probabilityBenign"] = frame["probabilityBenign"].astype(float)
    frame["probabilityPhishing"] = frame["probabilityPhishing"].astype(float)
    frame["probabilityMalware"] = frame["probabilityMalware"].astype(float)
    frame["isIpHost"] = frame["registrableDomain"].map(_is_ip_host)

    mapping = config.label_mapping
    labels = frame["label"].map(mapping).to_numpy(dtype=int)
    predicted = frame["predicted"].map(mapping).to_numpy(dtype=int)

    output_dir = config.path("error_analysis")
    output_dir.mkdir(parents=True, exist_ok=True)

    false_positive = (labels == 0) & (predicted != 0)
    false_negative = (labels != 0) & (predicted == 0)
    phishing_as_malware = (labels == 1) & (predicted == 2)
    malware_as_phishing = (labels == 2) & (predicted == 1)

    error_rows = [
        {
            "errorType": "benign_false_positive",
            "description": "BENIGN predicted as PHISHING or MALWARE",
            "count": int(false_positive.sum()),
        },
        {
            "errorType": "malicious_false_negative",
            "description": "PHISHING or MALWARE predicted as BENIGN",
            "count": int(false_negative.sum()),
        },
        {
            "errorType": "phishing_as_malware",
            "description": "PHISHING predicted as MALWARE",
            "count": int(phishing_as_malware.sum()),
        },
        {
            "errorType": "malware_as_phishing",
            "description": "MALWARE predicted as PHISHING",
            "count": int(malware_as_phishing.sum()),
        },
    ]
    error_summary = pd.DataFrame(error_rows)
    error_summary["testRowCount"] = int(len(frame))
    error_summary["errorRate"] = error_summary["count"] / max(1, int(len(frame)))
    error_summary.to_csv(output_dir / "error_summary.csv", index=False)

    details = pd.concat(
        [
            _error_rows(frame, false_positive, "benign_false_positive"),
            _error_rows(frame, false_negative, "malicious_false_negative"),
        ],
        ignore_index=True,
    )
    details.to_csv(output_dir / "error_details.csv", index=False)

    subgroup_rows = []
    for name, mask in (
        ("all", pd.Series(True, index=frame.index)),
        ("ip_host", frame["isIpHost"]),
        ("non_ip_host", ~frame["isIpHost"]),
    ):
        metrics = _subgroup_metrics(labels[mask.to_numpy()], predicted[mask.to_numpy()])
        subgroup_rows.append({"subgroup": name, **metrics})
    for source, group in frame.groupby("source", sort=True):
        mask = frame["source"].eq(source)
        metrics = _subgroup_metrics(labels[mask.to_numpy()], predicted[mask.to_numpy()])
        subgroup_rows.append({"subgroup": f"source:{source}", **metrics})
    for label_name in LABEL_NAMES:
        mask = frame["label"].eq(label_name)
        if not mask.any():
            continue
        metrics = _subgroup_metrics(labels[mask.to_numpy()], predicted[mask.to_numpy()])
        subgroup_rows.append({"subgroup": f"label:{label_name}", **metrics})
    subgroup_table = pd.DataFrame(subgroup_rows)
    subgroup_table.to_csv(output_dir / "subgroup_metrics.csv", index=False)

    source_rows = []
    probability_columns = {
        0: "probabilityBenign",
        1: "probabilityPhishing",
        2: "probabilityMalware",
    }
    for (source, label), group in frame.groupby(["source", "label"], sort=True):
        group_labels = group["label"].map(mapping).to_numpy(dtype=int)
        group_predicted = group["predicted"].map(mapping).to_numpy(dtype=int)
        source_rows.append(
            {
                "source": source,
                "label": label,
                "sampleCount": int(len(group)),
                "accuracy": float(accuracy_score(group_labels, group_predicted)),
                "recall": float((group_predicted == group_labels[0]).mean())
                if len(group_labels)
                else None,
                "ipHostShare": float(group["isIpHost"].mean()),
                "meanProbabilityTrueClass": float(
                    np.mean(
                        [
                            group[probability_columns[int(true)]].iloc[index]
                            for index, true in enumerate(group_labels)
                        ]
                    )
                ),
            }
        )
    source_table = pd.DataFrame(source_rows)
    source_table.to_csv(output_dir / "source_bias_metrics.csv", index=False)

    ip_metrics = subgroup_table[subgroup_table["subgroup"] == "ip_host"].iloc[0]
    non_ip_metrics = subgroup_table[subgroup_table["subgroup"] == "non_ip_host"].iloc[0]
    comparison_path = config.path("metrics").parents[1] / "baseline_comparison.csv"
    comparison = pd.read_csv(comparison_path) if comparison_path.exists() else pd.DataFrame()

    def _lookup(model: str, column: str) -> float | None:
        if comparison.empty:
            return None
        rows = comparison[comparison["Model"] == model]
        if rows.empty:
            return None
        return float(rows.iloc[0][column])

    report = [
        "# URLBERT Error Analysis (frozen DOMAIN_ONLY Test Set)",
        "",
        "This report is derived from a single official Test evaluation.",
        "Domain strings are hashed or redacted; raw malicious hostnames are not exported here.",
        "Probabilities are UNCALIBRATED PROBABILITY and must not be read as confidence.",
        "",
        "## Error summary",
        "",
    ]
    report.extend(
        [
            f"- {row['description']}: {int(row['count'])} / {int(row['testRowCount'])} "
            f"({row['errorRate']:.4f})"
            for _, row in error_summary.iterrows()
        ]
    )
    report.extend(
        [
            "",
            "## IP-host subgroup",
            "",
            f"- IP-host rows: {int(ip_metrics['sampleCount'])}, accuracy {ip_metrics['accuracy']:.4f}, "
            f"macro F1 {ip_metrics['macroF1']:.4f}, MALWARE recall {ip_metrics['malwareRecall']}",
            f"- Non-IP rows: {int(non_ip_metrics['sampleCount'])}, accuracy {non_ip_metrics['accuracy']:.4f}, "
            f"macro F1 {non_ip_metrics['macroF1']:.4f}, MALWARE recall {non_ip_metrics['malwareRecall']}",
            "- The non-IP subgroup is a diagnostic subset only and does not replace the frozen Test Set.",
            "",
            "## LightGBM vs URLBERT on the same frozen Test Set",
            "",
        ]
    )
    for metric in ("Accuracy", "Macro F1", "Phishing Recall", "Malware Recall", "Benign FPR", "Malicious FNR"):
        lightgbm_value = _lookup(
            str(config.raw.get("comparison_lightgbm_model", "LightGBM Domain Only")), metric
        )
        urlbert_value = _lookup(
            str(config.raw.get("comparison_urlbert_model", "URLBERT Domain Only")), metric
        )
        if lightgbm_value is None or urlbert_value is None:
            continue
        report.append(f"- {metric}: LightGBM {lightgbm_value:.4f} vs URLBERT {urlbert_value:.4f}")
    report.extend(
        [
            "",
            "## Source bias",
            "",
            "See `source_bias_metrics.csv`. Per-source accuracy and recall are reported separately for "
            "CERT Polska, OpenPhish, and URLhaus so that provider-specific behaviour cannot be hidden by a "
            "single aggregate score.",
        ]
    )
    (output_dir / "error_analysis_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    summary = {
        "testRowCount": int(len(frame)),
        "benignFalsePositive": int(false_positive.sum()),
        "maliciousFalseNegative": int(false_negative.sum()),
        "ipHostCount": int(frame["isIpHost"].sum()),
        "nonIpHostCount": int((~frame["isIpHost"]).sum()),
        "outputs": [
            "error_summary.csv",
            "error_details.csv",
            "subgroup_metrics.csv",
            "source_bias_metrics.csv",
            "error_analysis_report.md",
        ],
    }
    (output_dir / "analysis_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LOGGER.info("Wrote URLBERT error analysis to %s", output_dir)
    return summary


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run URLBERT error, IP-subgroup and source-bias analysis")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    try:
        print(json.dumps(run_analysis(args.config), ensure_ascii=False, indent=2))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        LOGGER.error("%s", error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
