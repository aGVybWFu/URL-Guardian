from tests.test_splitter import fixture_frame
from src.data.splitter import domain_aware_split


def test_no_domain_leakage():
    train, validation, test = domain_aware_split(fixture_frame(), seed=42)
    train_domains = set(train["registrable_domain"])
    validation_domains = set(validation["registrable_domain"])
    test_domains = set(test["registrable_domain"])
    assert train_domains.isdisjoint(validation_domains)
    assert train_domains.isdisjoint(test_domains)
    assert validation_domains.isdisjoint(test_domains)

