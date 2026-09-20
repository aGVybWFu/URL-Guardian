from urllib.parse import parse_qs, urlsplit

from src.data.commoncrawl import collect_candidates, query_domain
from src.data.official_downloader import OfficialDownloadError


def test_commoncrawl_query_uses_domain_match_and_per_domain_cap(monkeypatch):
    requested = []

    def fake_fetch(url, timeout=120, source=None):
        requested.append(url)
        return (
            '{"url":"https://example.com/","mime":"text/html","status":"200"}\n'
            '{"url":"https://www.example.com/help","mime":"text/html","status":"200"}\n'
            '{"url":"https://sub.example.com/page?id=1","mime":"text/html","status":"200"}\n'
            '{"url":"https://unrelated.test/","mime":"text/html","status":"200"}\n'
        ).encode()

    monkeypatch.setattr("src.data.commoncrawl.fetch_official_bytes", fake_fetch)
    rows = query_domain("example.com", "CC-MAIN-2026-39", limit=2)
    query = parse_qs(urlsplit(requested[0]).query)
    assert query["url"] == ["example.com"]
    assert query["matchType"] == ["domain"]
    assert query["limit"] == ["25"]
    assert len(rows) == 2
    assert all("example.com" in str(row["url"]) for row in rows)


def test_commoncrawl_404_means_no_indexed_candidates(monkeypatch):
    def missing(*args, **kwargs):
        raise OfficialDownloadError("not found", status=404)

    monkeypatch.setattr("src.data.commoncrawl.fetch_official_bytes", missing)
    assert query_domain("example.test", "CC-MAIN-2026-39", limit=5) == []


def test_commoncrawl_retries_transient_disconnect(monkeypatch):
    attempts = 0

    def transient(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionResetError("temporary disconnect")
        return b'{"url":"https://example.test/page","mime":"text/html","status":"200"}\n'

    monkeypatch.setattr("src.data.commoncrawl.fetch_official_bytes", transient)
    monkeypatch.setattr("src.data.commoncrawl.time.sleep", lambda _: None)
    assert len(query_domain("example.test", "CC-MAIN-2026-39", limit=5)) == 1
    assert attempts == 3


def test_commoncrawl_collect_records_per_domain_service_failures(monkeypatch, tmp_path):
    def unavailable(*args, **kwargs):
        raise OfficialDownloadError("service unavailable", status=504)

    monkeypatch.setattr("src.data.commoncrawl.query_domain", unavailable)
    path, index_id, count, failures = collect_candidates(
        ["example.test"], tmp_path / "candidates.jsonl", per_domain=5, delay_seconds=0,
        index_id="CC-MAIN-2026-39"
    )
    assert index_id == "CC-MAIN-2026-39"
    assert count == 0
    assert failures == 1
    assert path.read_text(encoding="utf-8") == ""
