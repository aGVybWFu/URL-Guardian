import pandas as pd

from src.data.views import create_domain_only_view


def test_domain_only_representation_removes_path_query_and_scheme_artifacts(tmp_path):
    frame = pd.DataFrame(
        {
            "hostname": ["example.com", "login.example.test", "192.0.2.1"],
            "registrable_domain": ["example.com", "example.test", "192.0.2.1"],
            "label": ["BENIGN", "PHISHING", "MALWARE"],
            "normalized_url": ["https://example.com/a", "http://login.example.test/x?q=1", "http://192.0.2.1/file"],
        }
    )
    view = create_domain_only_view(frame, tmp_path / "conflicts.csv")
    assert set(view["model_url"]) == {"https://example.com/", "https://example.test/", "https://192.0.2.1/"}
    assert set(view["dataset_view"]) == {"DOMAIN_ONLY"}
