from __future__ import annotations

import json
import logging
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode

from .official_downloader import OfficialDownloadError, fetch_official_bytes
from .normalizer import URLNormalizationError, normalize_url

LOGGER = logging.getLogger(__name__)


def latest_index_id() -> str:
    catalogs = json.loads(fetch_official_bytes("https://index.commoncrawl.org/collinfo.json", timeout=60))
    if not catalogs or not catalogs[0].get("id"):
        raise RuntimeError("Common Crawl did not return an index catalog")
    return str(catalogs[0]["id"])


def query_domain(domain: str, index_id: str, limit: int = 5) -> list[dict[str, object]]:
    if limit <= 0:
        raise ValueError("Common Crawl per-domain limit must be positive")
    query = urlencode(
        [
            ("url", domain),
            ("matchType", "domain"),
            ("output", "json"),
            ("filter", "=status:200"),
            ("filter", "=mime:text/html"),
            ("collapse", "urlkey"),
            ("fl", "url,timestamp,mime,status,digest"),
            ("limit", str(max(25, limit * 5))),
        ]
    )
    endpoint = f"https://index.commoncrawl.org/{index_id}-index?{query}"
    payload = ""
    for attempt in range(3):
        try:
            payload = fetch_official_bytes(endpoint, timeout=60).decode("utf-8")
            break
        except (urllib.error.HTTPError, OfficialDownloadError, OSError) as error:
            status = error.code if isinstance(error, urllib.error.HTTPError) else getattr(error, "status", None)
            if status == 404:
                return []
            if attempt == 2:
                raise
            time.sleep(2**attempt)
    rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
    accepted: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in rows:
        try:
            parsed = normalize_url(str(item.get("url", "")))
        except (URLNormalizationError, TypeError, ValueError):
            continue
        if parsed.registrable_domain != domain or parsed.normalized_url in seen:
            continue
        seen.add(parsed.normalized_url)
        item["url"] = parsed.normalized_url
        accepted.append(item)
        if len(accepted) >= limit:
            break
    return accepted


def collect_candidates(
    domains: list[str],
    output: str | Path,
    per_domain: int = 1,
    delay_seconds: float = 0.2,
    index_id: str | None = None,
    workers: int = 1,
    resume: bool = False,
) -> tuple[Path, str, int, int]:
    if per_domain <= 0:
        raise ValueError("Common Crawl per-domain limit must be positive")
    if delay_seconds < 0:
        raise ValueError("Common Crawl delay cannot be negative")
    if workers <= 0:
        raise ValueError("Common Crawl worker count must be positive")
    crawl_id = index_id or latest_index_id()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    progress_path = path.with_suffix(path.suffix + ".progress.jsonl")
    completed: set[str] = set()
    count = 0
    if resume and path.exists() and progress_path.exists():
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        for line in progress_path.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if item.get("status") in {"success", "empty"}:
                completed.add(str(item["domain"]))
    pending = [domain for domain in domains if domain not in completed]
    failures = 0
    failure_path = path.with_suffix(path.suffix + ".failures.jsonl")
    mode = "a" if resume and path.exists() else "w"

    def collect_one(domain: str) -> tuple[str, list[dict[str, object]], str | None]:
        try:
            return domain, query_domain(domain, crawl_id, per_domain), None
        except (OSError, OfficialDownloadError, UnicodeError, json.JSONDecodeError, TimeoutError) as error:
            return domain, [], f"{type(error).__name__}: {error}"
        finally:
            if delay_seconds:
                time.sleep(delay_seconds)

    with path.open(mode, encoding="utf-8", newline="\n", buffering=1) as handle:
        with failure_path.open("w", encoding="utf-8", newline="\n") as failure_handle:
            progress_mode = "a" if resume and progress_path.exists() else "w"
            with progress_path.open(progress_mode, encoding="utf-8", newline="\n", buffering=1) as progress_handle:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    results = executor.map(collect_one, pending)
                    for position, (domain, rows, error) in enumerate(results, len(completed) + 1):
                        if error:
                            failure_handle.write(json.dumps({"domain": domain, "error": error}) + "\n")
                            progress_handle.write(json.dumps({"domain": domain, "status": "failure"}) + "\n")
                            failures += 1
                            continue
                        for item in rows:
                            item["tranco_domain"] = domain
                            item["commoncrawl_index"] = crawl_id
                            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
                            count += 1
                        status = "success" if rows else "empty"
                        progress_handle.write(json.dumps({"domain": domain, "status": status}) + "\n")
                        if position % 100 == 0 or position == len(domains):
                            LOGGER.info(
                                "Common Crawl progress %d/%d domains; candidates=%d; failures=%d",
                                position,
                                len(domains),
                                count,
                                failures,
                            )
    if failures == 0:
        failure_path.unlink(missing_ok=True)
    return path, crawl_id, count, failures
