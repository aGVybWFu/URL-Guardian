import pandas as pd

from src.data.splitter import assert_no_domain_leakage, domain_aware_split


def fixture_frame():
    rows = []
    labels = ["BENIGN", "PHISHING", "MALWARE"]
    for index in range(36):
        label = labels[index % 3]
        domain = f"domain-{index}.test"
        rows.append({"normalized_url": f"https://{domain}/{label.lower()}", "registrable_domain": domain, "label": label})
        rows.append({"normalized_url": f"https://sub.{domain}/second", "registrable_domain": domain, "label": label})
    return pd.DataFrame(rows)


def test_domain_aware_split_is_deterministic():
    first = domain_aware_split(fixture_frame(), seed=42)
    second = domain_aware_split(fixture_frame(), seed=42)
    assert [part["normalized_url"].tolist() for part in first] == [part["normalized_url"].tolist() for part in second]
    assert_no_domain_leakage(*first)
    assert all(set(part["label"]) == {"BENIGN", "PHISHING", "MALWARE"} for part in first)

