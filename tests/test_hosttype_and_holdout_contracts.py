"""Host-type sampling, feature-ablation, source-holdout and temporal contract tests."""

import json
from pathlib import Path

import pandas as pd
import pytest

from src.data.hosttype import artifact_controlled_malware_sample
from src.data.temporal import (
    TEMPORAL_STATUS_PENDING,
    TEMPORAL_STATUS_READY,
    build_temporal_split,
    evaluate_temporal_contract,
    rows_per_collected_date,
)
from src.models.lightgbm_v2 import IP_FEATURES, _feature_list
from src.features.schema import FEATURE_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]


def _malware_frame(domain_count: int, ip_count: int) -> pd.DataFrame:
    rows = []
    for index in range(domain_count):
        rows.append(
            {
                "label": "MALWARE",
                "source": "fixture",
                "registrable_domain": f"malware-{index}.example.com",
                "model_url": f"https://malware-{index}.example.com/",
            }
        )
    for index in range(ip_count):
        rows.append(
            {
                "label": "MALWARE",
                "source": "fixture",
                "registrable_domain": f"192.0.2.{index + 1}",
                "model_url": f"https://192.0.2.{index + 1}/",
            }
        )
    for index in range(20):
        rows.append(
            {
                "label": "BENIGN",
                "source": "fixture",
                "registrable_domain": f"benign-{index}.example.com",
                "model_url": f"https://benign-{index}.example.com/",
            }
        )
    return pd.DataFrame(rows)


def test_artifact_control_keeps_all_domain_malware_and_caps_ip_malware():
    frame = _malware_frame(domain_count=30, ip_count=90)
    controlled, rationale = artifact_controlled_malware_sample(frame, seed=42)
    malware = controlled[controlled["label"] == "MALWARE"]
    domains = malware["registrable_domain"].str.contains("example.com").sum()
    ips = len(malware) - domains
    assert domains == 30
    assert ips == 30
    assert rationale["ipHostRecordsDropped"] == 60
    assert rationale["syntheticRowsCreated"] == 0
    assert rationale["duplicateRowsCreated"] == 0
    assert rationale["resultingIpShare"] == pytest.approx(0.5)


def test_artifact_control_never_invents_rows_when_ip_pool_is_small():
    frame = _malware_frame(domain_count=30, ip_count=5)
    controlled, rationale = artifact_controlled_malware_sample(frame, seed=42)
    malware = controlled[controlled["label"] == "MALWARE"]
    assert len(malware) == 35
    assert rationale["ipHostRecordsDropped"] == 0
    assert rationale["resultingIpShare"] == pytest.approx(5 / 35)


def test_artifact_control_keeps_benign_and_phishing_untouched():
    frame = _malware_frame(domain_count=10, ip_count=10)
    controlled, _ = artifact_controlled_malware_sample(frame, seed=42)
    assert len(controlled[controlled["label"] == "BENIGN"]) == 20


def test_artifact_control_is_deterministic():
    frame = _malware_frame(domain_count=20, ip_count=60)
    first, _ = artifact_controlled_malware_sample(frame, seed=7)
    second, _ = artifact_controlled_malware_sample(frame, seed=7)
    assert first["registrable_domain"].tolist() == second["registrable_domain"].tolist()


def test_no_ip_feature_ablation_removes_exactly_the_ip_indicators():
    full = _feature_list([])
    ablated = _feature_list(IP_FEATURES)
    assert full == list(FEATURE_NAMES)
    assert set(full) - set(ablated) == set(IP_FEATURES)
    assert "has_ip_address" not in ablated
    assert "has_ipv4" not in ablated
    assert "has_ipv6" not in ablated
    assert len(ablated) == len(full) - 3


def test_ablation_experiments_are_declared_in_code():
    from src.models.lightgbm_v2 import EXPERIMENTS

    assert EXPERIMENTS["full"]["excludedFeatures"] == []
    assert EXPERIMENTS["no_ip"]["excludedFeatures"] == IP_FEATURES
    assert EXPERIMENTS["no_ip"]["experimentId"].endswith("NOIP")


def test_source_holdout_removes_the_source_from_training_only():
    source = (REPO_ROOT / "src" / "evaluation" / "phase25.py").read_text(encoding="utf-8")
    assert 'train["source"].astype(str) != held_out_source' in source
    assert 'validation["source"].astype(str) != held_out_source' in source
    assert "test Set is untouched" in source or "Test Set is untouched" in source
    assert '"evaluationType": "external-source-holdout"' in source


def test_source_holdout_marks_seen_sources_as_subgroups_not_external():
    source = (REPO_ROOT / "src" / "evaluation" / "phase25.py").read_text(encoding="utf-8")
    assert "seenSourcesMetrics" in source
    assert "heldOutSourceMetrics" in source


def test_temporal_contract_is_pending_with_a_single_snapshot_date(tmp_path):
    snapshots = tmp_path / "snapshots" / "2026-09-20"
    snapshots.mkdir(parents=True)
    (snapshots / "snapshot_metadata.json").write_text(
        json.dumps({"snapshot_id": "snapshot-2026-09-20", "sources": []}), encoding="utf-8"
    )
    contract = evaluate_temporal_contract(tmp_path)
    assert contract.status == TEMPORAL_STATUS_PENDING
    assert contract.is_ready is False
    assert contract.snapshot_dates == ["2026-09-20"]
    assert "fabricated" in contract.reason


def test_temporal_contract_becomes_ready_with_two_snapshot_dates(tmp_path):
    for day in ("2026-09-01", "2026-09-20"):
        directory = tmp_path / "snapshots" / day
        directory.mkdir(parents=True)
        (directory / "snapshot_metadata.json").write_text(
            json.dumps({"snapshot_id": f"snapshot-{day}", "sources": []}), encoding="utf-8"
        )
    contract = evaluate_temporal_contract(tmp_path)
    assert contract.status == TEMPORAL_STATUS_READY
    assert contract.train_validation_dates == ["2026-09-01"]
    assert contract.temporal_test_dates == ["2026-09-20"]


def test_temporal_split_refuses_to_run_while_pending(tmp_path):
    contract = evaluate_temporal_contract(tmp_path)
    with pytest.raises(RuntimeError, match="not available"):
        build_temporal_split(pd.DataFrame({"collected_at": ["2026-09-20"]}), contract)


def test_temporal_split_uses_strictly_later_dates_for_the_test(tmp_path):
    for day in ("2026-09-01", "2026-09-20"):
        directory = tmp_path / "snapshots" / day
        directory.mkdir(parents=True)
        (directory / "snapshot_metadata.json").write_text(
            json.dumps({"snapshot_id": f"snapshot-{day}", "sources": []}), encoding="utf-8"
        )
    contract = evaluate_temporal_contract(tmp_path)
    frame = pd.DataFrame(
        {
            "collected_at": ["2026-09-01", "2026-09-20", "2026-09-20"],
            "url": ["https://a.example.com/", "https://b.example.com/", "https://c.example.com/"],
        }
    )
    train, test = build_temporal_split(frame, contract)
    assert len(train) == 1
    assert len(test) == 2


def test_rows_per_collected_date_counts_valid_dates_only():
    frame = pd.DataFrame({"collected_at": ["2026-09-20", "2026-09-20", "", "not-a-date"]})
    assert rows_per_collected_date(frame) == {"2026-09-20": 2}


def test_official_temporal_contract_status_is_recorded():
    contract = evaluate_temporal_contract(REPO_ROOT / "data" / "raw")
    if not contract.snapshot_dates:
        pytest.skip("Raw snapshots are not present in this environment")
    assert contract.status in {TEMPORAL_STATUS_READY, TEMPORAL_STATUS_PENDING}
