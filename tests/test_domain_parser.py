from src.data.normalizer import normalize_url


def test_public_suffix_domains():
    assert normalize_url("https://accounts.google.com/x").registrable_domain == "google.com"
    assert normalize_url("https://google.com.attacker.xyz/x").registrable_domain == "attacker.xyz"
    assert normalize_url("https://shop.example.com.tw/x").registrable_domain == "example.com.tw"
    assert normalize_url("https://shop.example.co.uk/x").registrable_domain == "example.co.uk"
    assert normalize_url("https://shop.example.co.jp/x").registrable_domain == "example.co.jp"

