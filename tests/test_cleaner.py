import pandas as pd

from src.data.cleaner import clean_dataset


def test_cleaner_removes_duplicates_invalid_and_conflicts(tmp_path):
    frame = pd.DataFrame(
        [
            {"url": "https://example.com/a", "label": "BENIGN", "source": "fixture", "collected_at": ""},
            {"url": "HTTPS://EXAMPLE.COM./a", "label": "BENIGN", "source": "fixture", "collected_at": ""},
            {"url": "https://example.net/x", "label": "PHISHING", "source": "fixture", "collected_at": ""},
            {"url": "https://example.net/x", "label": "MALWARE", "source": "fixture2", "collected_at": ""},
            {"url": "ftp://example.org/a", "label": "MALWARE", "source": "fixture", "collected_at": ""},
            {"url": "", "label": "BENIGN", "source": "fixture", "collected_at": ""},
            {"url": "https://example.org/a", "label": "WRONG", "source": "fixture", "collected_at": ""},
        ]
    )
    conflicts = tmp_path / "conflicts.csv"
    clean, stats = clean_dataset(frame, conflicts)
    assert list(clean["normalized_url"]) == ["https://example.com/a"]
    assert stats.removed_normalized_duplicates == 1
    assert stats.removed_conflicts == 2
    assert stats.removed_invalid_urls == 1
    assert len(pd.read_csv(conflicts)) == 2

