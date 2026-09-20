from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from src.features.extractor import extract_feature_frame

CONTINUOUS = [
    "url_length",
    "hostname_length",
    "registrable_domain_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_character_count",
    "special_character_ratio",
    "digit_ratio",
    "percent_encoded_count",
    "parameter_count",
]
FLAGS = ["is_https", "is_http", "has_ip_address", "has_ipv4", "has_ipv6", "has_punycode"]


def _enriched(frame: pd.DataFrame) -> pd.DataFrame:
    features = extract_feature_frame(frame["model_url"])
    output = pd.concat([frame.reset_index(drop=True), features], axis=1)
    output["has_path"] = (output["path_length"] > 0).astype(int)
    output["has_query"] = (output["query_length"] > 0).astype(int)
    return output


def _distribution_plot(data: pd.DataFrame, column: str, output: Path) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(12, 4), sharey=False)
    for axis, (view, group) in zip(axes, data.groupby("dataset_view", sort=True)):
        for label, label_group in group.groupby("label", sort=True):
            clipped = label_group[column].clip(upper=label_group[column].quantile(0.99))
            axis.hist(clipped, bins=40, alpha=0.45, label=label)
        axis.set(title=view, xlabel=column, ylabel="Records")
        axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=160)
    plt.close(figure)


def audit_dataset_views(views: dict[str, pd.DataFrame], output_dir: str | Path) -> dict[str, object]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    enriched = pd.concat([_enriched(frame) for frame in views.values()], ignore_index=True)
    rows: list[dict[str, object]] = []
    warnings: list[str] = []
    for (view, label), group in enriched.groupby(["dataset_view", "label"], sort=True):
        row: dict[str, object] = {"dataset_view": view, "label": label, "count": len(group)}
        for column in CONTINUOUS:
            row[f"{column}_mean"] = float(group[column].mean())
            row[f"{column}_median"] = float(group[column].median())
        for column in [*FLAGS, "has_path", "has_query"]:
            row[f"{column}_percent"] = float(group[column].mean() * 100)
        rows.append(row)
    summary = pd.DataFrame(rows)
    summary.to_csv(directory / "dataset_bias_summary.csv", index=False)
    source_table = pd.crosstab(
        [enriched["dataset_view"], enriched["label"]], enriched["source"], margins=True
    )
    source_table.to_csv(directory / "class_source_distribution.csv")
    for column in ("url_length", "path_length", "query_length"):
        _distribution_plot(enriched, column, directory / f"{column}_distribution.png")
    scheme = (
        enriched.groupby(["dataset_view", "label"])[["is_https", "is_http"]]
        .mean()
        .mul(100)
        .rename(columns={"is_https": "HTTPS", "is_http": "HTTP"})
    )
    axis = scheme.plot(kind="bar", figsize=(10, 5), color=["#237a8b", "#d95f02"])
    axis.set(title="Scheme distribution by dataset view and class", xlabel="View / Class", ylabel="Percent")
    axis.figure.tight_layout()
    axis.figure.savefig(directory / "scheme_distribution.png", dpi=160)
    plt.close(axis.figure)

    for view, view_summary in summary.groupby("dataset_view"):
        for metric in ("has_path_percent", "has_query_percent", "is_https_percent", "has_ip_address_percent"):
            spread = float(view_summary[metric].max() - view_summary[metric].min())
            if spread >= 40:
                warnings.append(
                    f"Possible dataset source artifact: {view} {metric} differs by "
                    f"{spread:.1f} percentage points across classes."
                )
    source_purity = enriched.groupby(["dataset_view", "source"])["label"].nunique()
    if (source_purity == 1).all():
        warnings.append(
            "Possible dataset source artifact: every observed source maps to only one label; "
            "source/class confounding is present."
        )
    report_lines = [
        "# Dataset Bias Audit",
        "",
        "Accuracy alone can hide costly false positives, false negatives, and poor minority-class recall. "
        "Model comparisons must also use malicious FNR, benign FPR, phishing recall, and AUPRC.",
        "",
        "## Detected artifacts",
        "",
    ]
    report_lines.extend([f"- {warning}" for warning in warnings] or ["- No threshold-based artifact was detected."])
    report_lines.extend(
        [
            "",
            "These checks describe representation and source differences; they do not prove causality. "
            "Review the CSV and plots before treating any model result as a security finding.",
        ]
    )
    (directory / "dataset_bias_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return {"rows": len(enriched), "warnings": warnings}
