"""Versioned, curated brand and shortener catalogs (BrandCatalogV1 / ShortenerCatalogV1).

The catalogs are deliberately small, human-reviewed research data. They are not
scraped, not exhaustive and not a security guarantee. A brand token match raises
a review signal; only the official-domain check suppresses the impersonation
signal, and it never suppresses the confirmed-malicious guardrail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

BRAND_CATALOG_VERSION = "BrandCatalogV1"
SHORTENER_CATALOG_VERSION = "ShortenerCatalogV1"


@dataclass(frozen=True)
class BrandEntry:
    brand_id: str
    display_name: str
    canonical_domains: tuple[str, ...]
    aliases: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "brandId": self.brand_id,
            "displayName": self.display_name,
            "canonicalDomains": list(self.canonical_domains),
            "aliases": list(self.aliases),
        }


BRAND_CATALOG: tuple[BrandEntry, ...] = (
    BrandEntry("paypal", "PayPal", ("paypal.com", "paypal.me"), ("paypal",)),
    BrandEntry(
        "microsoft", "Microsoft",
        ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
        ("microsoft", "office365", "outlook", "onedrive", "hotmail", "xbox", "windows"),
    ),
    BrandEntry("google", "Google", ("google.com", "gmail.com", "youtube.com"), ("google", "gmail", "youtube")),
    BrandEntry("apple", "Apple", ("apple.com", "icloud.com"), ("apple", "icloud", "itunes", "appleid")),
    BrandEntry(
        "amazon", "Amazon", ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp"),
        ("amazon", "amazonaws"),
    ),
    BrandEntry(
        "meta", "Meta", ("facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"),
        ("facebook", "instagram", "whatsapp", "messenger"),
    ),
    BrandEntry("netflix", "Netflix", ("netflix.com",), ("netflix",)),
    BrandEntry("steam", "Steam", ("steampowered.com", "steamcommunity.com"), ("steam", "steamcommunity")),
    BrandEntry("epicgames", "Epic Games", ("epicgames.com",), ("epicgames",)),
    BrandEntry("roblox", "Roblox", ("roblox.com",), ("roblox",)),
    BrandEntry("discord", "Discord", ("discord.com",), ("discord",)),
    BrandEntry("telegram", "Telegram", ("telegram.org",), ("telegram",)),
    BrandEntry("binance", "Binance", ("binance.com",), ("binance",)),
    BrandEntry("coinbase", "Coinbase", ("coinbase.com",), ("coinbase",)),
    BrandEntry("metamask", "MetaMask", ("metamask.io",), ("metamask",)),
    BrandEntry("trustwallet", "Trust Wallet", ("trustwallet.com",), ("trustwallet",)),
    BrandEntry("blockchain", "Blockchain.com", ("blockchain.com",), ("blockchain",)),
    BrandEntry("kraken", "Kraken", ("kraken.com",), ("kraken",)),
    BrandEntry("chase", "Chase", ("chase.com",), ("chase",)),
    BrandEntry("bankofamerica", "Bank of America", ("bankofamerica.com",), ("bankofamerica",)),
    BrandEntry("wellsfargo", "Wells Fargo", ("wellsfargo.com",), ("wellsfargo",)),
    BrandEntry("citibank", "Citibank", ("citibank.com", "citi.com"), ("citibank",)),
    BrandEntry("hsbc", "HSBC", ("hsbc.com", "hsbc.co.uk"), ("hsbc",)),
    BrandEntry("americanexpress", "American Express", ("americanexpress.com", "amex.com"), ("americanexpress", "amex")),
    BrandEntry("visa", "Visa", ("visa.com",), ("visa",)),
    BrandEntry("mastercard", "Mastercard", ("mastercard.com",), ("mastercard",)),
    BrandEntry("revolut", "Revolut", ("revolut.com",), ("revolut",)),
    BrandEntry("dhl", "DHL", ("dhl.com",), ("dhl",)),
    BrandEntry("fedex", "FedEx", ("fedex.com",), ("fedex",)),
    BrandEntry("ups", "UPS", ("ups.com",), ("ups",)),
    BrandEntry("usps", "USPS", ("usps.com",), ("usps",)),
    BrandEntry("linkedin", "LinkedIn", ("linkedin.com",), ("linkedin",)),
    BrandEntry("x", "X", ("x.com", "twitter.com"), ("twitter",)),
    BrandEntry("tiktok", "TikTok", ("tiktok.com",), ("tiktok",)),
    BrandEntry("snapchat", "Snapchat", ("snapchat.com",), ("snapchat",)),
    BrandEntry("spotify", "Spotify", ("spotify.com",), ("spotify",)),
    BrandEntry("adobe", "Adobe", ("adobe.com",), ("adobe",)),
    BrandEntry("dropbox", "Dropbox", ("dropbox.com",), ("dropbox",)),
    BrandEntry("github", "GitHub", ("github.com",), ("github",)),
    BrandEntry("gitlab", "GitLab", ("gitlab.com",), ("gitlab",)),
    BrandEntry(
        "alibaba", "Alibaba", ("alibaba.com", "taobao.com", "tmall.com", "aliexpress.com"),
        ("alibaba", "taobao", "tmall", "aliexpress"),
    ),
    BrandEntry("tencent", "Tencent", ("qq.com", "tencent.com", "wechat.com"), ("tencent", "wechat", "weixin")),
    BrandEntry("line", "LINE", ("line.me",), ("line",)),
    BrandEntry("yahoo", "Yahoo", ("yahoo.com", "yahoo.co.jp"), ("yahoo",)),
    BrandEntry("proton", "Proton", ("proton.me", "protonmail.com"), ("protonmail",)),
    BrandEntry("airbnb", "Airbnb", ("airbnb.com",), ("airbnb",)),
    BrandEntry("booking", "Booking.com", ("booking.com",), ("booking",)),
    BrandEntry("uber", "Uber", ("uber.com",), ("uber",)),
    BrandEntry("ebay", "eBay", ("ebay.com",), ("ebay",)),
    BrandEntry("walmart", "Walmart", ("walmart.com",), ("walmart",)),
    BrandEntry("nintendo", "Nintendo", ("nintendo.com",), ("nintendo",)),
    BrandEntry("playstation", "PlayStation", ("playstation.com",), ("playstation",)),
    BrandEntry("riotgames", "Riot Games", ("riotgames.com",), ("riotgames",)),
    BrandEntry("ubisoft", "Ubisoft", ("ubisoft.com",), ("ubisoft",)),
)

# Official platform shorteners (youtu.be, t.me, discord.gg) are intentionally
# excluded: their destination platform is identifiable from the domain itself,
# so treating them as opaque shorteners would only add noise.
SHORTENER_DOMAINS: tuple[str, ...] = (
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "v.gd", "tiny.cc",
    "lnkd.in", "s.id", "bit.do", "soo.gd", "clck.ru", "u.to", "short.io",
    "bl.ink", "snip.ly", "mcaf.ee", "adf.ly", "sh.st",
)

BRAND_BY_ID: dict[str, BrandEntry] = {entry.brand_id: entry for entry in BRAND_CATALOG}


def brand_catalog_payload() -> dict[str, Any]:
    return {
        "catalogVersion": BRAND_CATALOG_VERSION,
        "entryCount": len(BRAND_CATALOG),
        "entries": [entry.to_dict() for entry in BRAND_CATALOG],
    }


def shortener_catalog_payload() -> dict[str, Any]:
    return {
        "catalogVersion": SHORTENER_CATALOG_VERSION,
        "domainCount": len(SHORTENER_DOMAINS),
        "domains": list(SHORTENER_DOMAINS),
    }
