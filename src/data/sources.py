from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd


def _read_csv(path: Path, **kwargs: object) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str, on_bad_lines="error", **kwargs)


def parse_tranco(path: str | Path, list_id: str = "unknown", collected_at: str | None = None) -> pd.DataFrame:
    source_path = Path(path)
    frame = _read_csv(source_path, header=None, names=["rank", "domain"])
    frame["rank"] = pd.to_numeric(frame["rank"], errors="raise").astype("Int64")
    frame["domain"] = frame["domain"].astype("string").str.strip()
    return pd.DataFrame(
        {
            "url": "https://" + frame["domain"],
            "label": "BENIGN",
            "source": "tranco",
            "collected_at": collected_at,
            "rank": frame["rank"],
            "domain": frame["domain"],
            "tranco_list_id": list_id,
            "label_confidence": "candidate",
        }
    )


def parse_phishtank(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    frame = _read_csv(Path(path))
    required = {"phish_id", "url", "submission_time", "verification_time", "target"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"PhishTank feed is missing columns: {sorted(missing)}")
    if "verified" in frame:
        frame = frame[frame["verified"].str.lower().eq("yes")]
    if "online" in frame:
        frame = frame[frame["online"].str.lower().eq("yes")]
    result = frame.copy()
    result["label"] = "PHISHING"
    result["source"] = "phishtank"
    result["collected_at"] = collected_at
    result["label_confidence"] = "verified_online"
    return result


def parse_urlhaus(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    source_path = Path(path)
    header: list[str] | None = None
    with source_path.open("r", encoding="utf-8-sig", errors="strict") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped.startswith("#") and "," in stripped and "url" in stripped.lower():
                header = [item.strip() for item in stripped.lstrip("#").strip().split(",")]
                break
            if stripped and not stripped.startswith("#"):
                break
    frame = _read_csv(source_path, comment="#", names=header, header=None if header else "infer")
    lookup = {str(column).strip().lower(): str(column) for column in frame.columns}
    url_column = next((lookup[name] for name in ("url", "urlhaus_url") if name in lookup), None)
    if url_column is None:
        raise ValueError("URLhaus feed is missing a URL column")
    if url_column != "url":
        frame = frame.rename(columns={url_column: "url"})
    result = frame.copy()
    result["label"] = "MALWARE"
    result["source"] = "urlhaus"
    result["collected_at"] = collected_at
    result["label_confidence"] = "listed"
    return result


def parse_commoncrawl(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or not item.get("url"):
                raise ValueError(f"Invalid Common Crawl JSONL record at line {line_number}")
            rows.append(item)
    frame = pd.DataFrame(rows)
    frame["label"] = "BENIGN"
    frame["source"] = "commoncrawl_tranco_candidate"
    frame["collected_at"] = collected_at
    frame["label_confidence"] = "candidate"
    return frame


def parse_openphish(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    urls = [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8-sig", errors="strict").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not urls:
        raise ValueError("OpenPhish Community Feed is empty")
    return pd.DataFrame(
        {
            "url": urls,
            "label": "PHISHING",
            "source": "openphish",
            "collected_at": collected_at,
            "label_confidence": "community_feed",
            "feed_type": "community",
        }
    )


def parse_cert_polska(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig", errors="strict"))
    if not isinstance(payload, list):
        raise ValueError("CERT Polska feed must be a JSON array")
    rows: list[dict[str, object]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("CERT Polska feed contains a non-object record")
        lookup = {str(key).lower(): value for key, value in item.items()}
        domain = str(lookup.get("domainaddress", "")).strip().strip(".")
        if not domain or lookup.get("deletedate") not in (None, ""):
            continue
        rows.append(
            {
                "url": f"https://{domain}/",
                "label": "PHISHING",
                "source": "cert_polska",
                "collected_at": collected_at,
                "label_confidence": "active_warning_list",
                "source_scope": "poland",
                "domain": domain,
                "insert_date": lookup.get("insertdate"),
                "register_position_id": lookup.get("registerpositionid"),
            }
        )
    if not rows:
        raise ValueError("CERT Polska feed contains no active domains")
    return pd.DataFrame(rows)


@dataclass(frozen=True)
class OpenPhishProvider:
    source: str = "openphish"
    feed_type: str = "community"

    @staticmethod
    def parse(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
        return parse_openphish(path, collected_at)


@dataclass(frozen=True)
class CertPolskaProvider:
    source: str = "cert_polska"
    feed_type: str = "dangerous_websites_warning_list_v2_json"

    @staticmethod
    def parse(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
        return parse_cert_polska(path, collected_at)


@dataclass(frozen=True)
class PhishingDatabaseProvider:
    """Official Phishing.Database active-domain feed provider.

    Phishing.Database is a community-maintained project. Its records are treated
    as unverified community reports, not ground truth: the dataset records this
    provenance and the pipeline runs a cross-source conflict audit before any
    record is used for training.
    """

    source: str = "phishing_database"
    feed: str = "phishing-domains-ACTIVE"

    @staticmethod
    def parse(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
        return parse_phishing_database(path, collected_at)


def parse_phishing_database(path: str | Path, collected_at: str | None = None) -> pd.DataFrame:
    """Parse the Phishing.Database active-domain list into PHISHING rows."""

    lines = [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8-sig", errors="strict").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        raise ValueError("Phishing.Database feed is empty")
    return pd.DataFrame(
        {
            "url": [f"https://{value.strip().strip('.')}/" for value in lines],
            "label": "PHISHING",
            "source": "phishing_database",
            "collected_at": collected_at,
            "label_confidence": "community_report",
            "feed_type": "phishing-domains-ACTIVE",
        }
    )


@dataclass(frozen=True)
class ThreatFoxProvider:
    """Official abuse.ch ThreatFox provider.

    Only `ioc_type == domain` records are used. The default threat-type filter is
    `payload_delivery`, which is the closest semantic match to a malware payload
    delivery host. `botnet_cc` has a different meaning (command-and-control
    infrastructure) and is therefore excluded by default; enabling it would be a
    documented semantic label broadening, never an implicit one.
    """

    source: str = "threatfox"
    default_threat_types: tuple[str, ...] = ("payload_delivery",)

    def parse(
        self,
        payload: str | Path | dict[str, object],
        collected_at: str | None = None,
        threat_types: tuple[str, ...] | None = None,
    ) -> pd.DataFrame:
        return parse_threatfox(payload, collected_at, threat_types or self.default_threat_types)


def parse_threatfox(
    payload: str | Path | dict[str, object],
    collected_at: str | None = None,
    threat_types: tuple[str, ...] = ("payload_delivery",),
) -> pd.DataFrame:
    """Parse a ThreatFox API response or export payload into MALWARE rows.

    Only domain IOCs from the approved threat types are converted. Hash and
    ip:port IOCs are ignored because they are not URL/domain strings.
    """

    if isinstance(payload, (str, Path)):
        data = json.loads(Path(payload).read_text(encoding="utf-8-sig", errors="strict"))
    else:
        data = payload
    if not isinstance(data, dict):
        raise ValueError("ThreatFox payload must be a mapping")
    status = str(data.get("query_status", "ok"))
    records = data.get("data")
    if records is None:
        raise ValueError("ThreatFox payload does not contain a data field")
    if not isinstance(records, list):
        raise ValueError("ThreatFox data field must be a list")
    if status not in {"ok"} and not records:
        raise ValueError(f"ThreatFox query did not succeed: {status}")
    allowed = {str(value) for value in threat_types}
    rows: list[dict[str, object]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        if str(item.get("ioc_type", "")).lower() != "domain":
            continue
        threat_type = str(item.get("threat_type", "")).lower()
        if allowed and threat_type not in allowed:
            continue
        ioc = str(item.get("ioc", "")).strip().strip(".")
        if not ioc:
            continue
        rows.append(
            {
                "url": f"https://{ioc}/",
                "label": "MALWARE",
                "source": "threatfox",
                "collected_at": collected_at,
                "label_confidence": "confirmed_ioc",
                "ioc_type": "domain",
                "threat_type": threat_type,
                "threat_type_desc": item.get("threat_type_desc"),
                "malware": item.get("malware"),
                "malware_printable": item.get("malware_printable"),
                "confidence_level": item.get("confidence_level"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "threatfox_id": item.get("id"),
                "tags": ", ".join(item.get("tags") or []) if isinstance(item.get("tags"), list) else item.get("tags"),
            }
        )
    if not rows:
        raise ValueError("ThreatFox payload contains no usable domain IOCs for the approved threat types")
    return pd.DataFrame(rows)


PARSERS = {
    "tranco": parse_tranco,
    "phishtank": parse_phishtank,
    "urlhaus": parse_urlhaus,
    "commoncrawl": parse_commoncrawl,
    "openphish": parse_openphish,
    "cert_polska": parse_cert_polska,
    "threatfox": parse_threatfox,
    "phishing_database": parse_phishing_database,
}
