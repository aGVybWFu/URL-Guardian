import pandas as pd

from src.evaluation.dataset_bias import audit_dataset_views


def _view(name: str) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"model_url": "https://normal.example/", "label": "BENIGN", "source": "safe", "dataset_view": name},
            {"model_url": "http://login.example.test/a?x=1", "label": "PHISHING", "source": "safe-phish", "dataset_view": name},
            {"model_url": "http://192.0.2.1/file.exe", "label": "MALWARE", "source": "safe-malware", "dataset_view": name},
        ]
    )


def test_dataset_bias_outputs_required_reports(tmp_path):
    result = audit_dataset_views({"domain_only": _view("DOMAIN_ONLY"), "full_url": _view("FULL_URL")}, tmp_path)
    assert result["rows"] == 6
    for name in (
        "dataset_bias_summary.csv",
        "url_length_distribution.png",
        "path_length_distribution.png",
        "query_length_distribution.png",
        "scheme_distribution.png",
        "class_source_distribution.csv",
        "dataset_bias_report.md",
    ):
        assert (tmp_path / name).exists()
    summary = pd.read_csv(tmp_path / "dataset_bias_summary.csv")
    for field in (
        "registrable_domain_length_mean",
        "hyphen_count_mean",
        "digit_count_mean",
        "special_character_ratio_mean",
        "percent_encoded_count_mean",
        "parameter_count_mean",
        "has_ipv4_percent",
        "has_ipv6_percent",
    ):
        assert field in summary.columns
    report = (tmp_path / "dataset_bias_report.md").read_text(encoding="utf-8")
    assert "Possible dataset source artifact" in report
