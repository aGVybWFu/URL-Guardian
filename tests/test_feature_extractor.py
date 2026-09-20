from src.features.extractor import extract_features
from src.features.schema import FEATURE_NAMES, feature_schema


def test_feature_extraction_for_structural_cases():
    features = extract_features("http://user@192.0.2.20:8080/login_verify?q=%2F#x")
    assert features["has_ipv4"] == 1
    assert features["has_ip_address"] == 1
    assert features["has_at_symbol"] == 1
    assert features["has_non_default_port"] == 1
    assert features["has_fragment"] == 1
    assert features["contains_login"] == 1
    assert features["contains_verify"] == 1
    assert features["percent_encoded_count"] == 1
    assert list(features) == FEATURE_NAMES


def test_schema_has_no_leakage_fields():
    names = {item["name"] for item in feature_schema()["features"]}
    assert "label" not in names
    assert "source" not in names
    assert len(names) == len(FEATURE_NAMES) >= 40


def test_punycode_feature():
    assert extract_features("https://xn--r8jz45g.xn--zckzah/")["has_punycode"] == 1

