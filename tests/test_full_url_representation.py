import pandas as pd

from src.data.views import create_full_url_view


def test_full_url_representation_uses_commoncrawl_for_benign_not_tranco_roots():
    frame = pd.DataFrame(
        [
            {"normalized_url": "https://example.com", "label": "BENIGN", "source": "tranco"},
            {"normalized_url": "https://example.com/article", "label": "BENIGN", "source": "commoncrawl_tranco_candidate"},
            {"normalized_url": "http://login.example.test/a", "label": "PHISHING", "source": "phishtank"},
            {"normalized_url": "https://domain-only.example.test/", "label": "PHISHING", "source": "cert_polska"},
            {"normalized_url": "http://192.0.2.1/file", "label": "MALWARE", "source": "urlhaus"},
        ]
    )
    view = create_full_url_view(frame)
    assert "https://example.com" not in set(view["model_url"])
    assert "https://example.com/article" in set(view["model_url"])
    assert "https://domain-only.example.test/" not in set(view["model_url"])
    assert set(view["label"]) == {"BENIGN", "PHISHING", "MALWARE"}
