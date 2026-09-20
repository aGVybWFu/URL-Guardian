import bz2
import json

import pandas as pd

from src.data.sources import (
    CertPolskaProvider,
    OpenPhishProvider,
    parse_cert_polska,
    parse_openphish,
    parse_phishtank,
    parse_tranco,
    parse_urlhaus,
)


def test_official_source_parsers_preserve_research_metadata(tmp_path):
    tranco = tmp_path / "tranco.csv"
    tranco.write_text("1,example.com\n2,example.net\n", encoding="utf-8")
    tranco_frame = parse_tranco(tranco, list_id="ABCD", collected_at="2026-09-20")
    assert tranco_frame.loc[0, "rank"] == 1
    assert tranco_frame.loc[0, "tranco_list_id"] == "ABCD"

    phish = tmp_path / "online-valid.csv.bz2"
    payload = (
        "phish_id,url,submission_time,verified,verification_time,online,target\n"
        "7,http://login.example.test/a,2026-01-01,yes,2026-01-02,yes,Example\n"
    )
    phish.write_bytes(bz2.compress(payload.encode("utf-8")))
    phish_frame = parse_phishtank(phish, "2026-09-20")
    assert phish_frame.loc[0, "phish_id"] == "7"
    assert phish_frame.loc[0, "target"] == "Example"

    urlhaus = tmp_path / "recent.csv"
    pd.DataFrame({"id": [9], "url": ["http://malware.example.test/file.exe"], "threat": ["malware_download"]}).to_csv(urlhaus, index=False)
    malware_frame = parse_urlhaus(urlhaus, "2026-09-20")
    assert malware_frame.loc[0, "label"] == "MALWARE"
    assert malware_frame.loc[0, "threat"] == "malware_download"

    commented = tmp_path / "urlhaus-commented.csv"
    commented.write_text(
        "# generated export\n# id,dateadded,url,threat\n10,2026-09-20,http://203.0.113.5/a.exe,malware_download\n",
        encoding="utf-8",
    )
    commented_frame = parse_urlhaus(commented, "2026-09-20")
    assert commented_frame.loc[0, "id"] == "10"


def test_openphish_community_feed_parser(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("https://login.example.test/a\nhttp://verify.example.test/b\n", encoding="utf-8")
    frame = parse_openphish(feed, "2026-09-20")
    assert len(frame) == 2
    assert set(frame["label"]) == {"PHISHING"}
    assert set(frame["source"]) == {"openphish"}
    assert set(frame["feed_type"]) == {"community"}
    assert OpenPhishProvider().parse(feed, "2026-09-20").equals(frame)


def test_cert_polska_parser_keeps_only_active_domains(tmp_path):
    feed = tmp_path / "domains.json"
    feed.write_text(
        json.dumps(
            [
                {
                    "RegisterPositionId": 1,
                    "DomainAddress": "fraud.example.test",
                    "InsertDate": "2026-09-20T00:00:00+00:00",
                    "DeleteDate": None,
                },
                {
                    "RegisterPositionId": 2,
                    "DomainAddress": "removed.example.test",
                    "InsertDate": "2026-09-19T00:00:00+00:00",
                    "DeleteDate": "2026-09-20T00:00:00+00:00",
                },
            ]
        ),
        encoding="utf-8",
    )
    frame = parse_cert_polska(feed, "2026-09-20")
    assert frame["url"].tolist() == ["https://fraud.example.test/"]
    assert frame.loc[0, "source_scope"] == "poland"
    assert CertPolskaProvider().parse(feed, "2026-09-20").equals(frame)
