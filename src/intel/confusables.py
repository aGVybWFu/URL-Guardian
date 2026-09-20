"""Deterministic confusable-skeleton normalisation for brand matching.

This is a documented heuristic for homoglyph and leetspeak obfuscation
(Cyrillic/Greek lookalikes, digit substitutions such as `0`->`o` and `1`->`l`,
and the `rn`->`m` / `vv`->`w` digraphs). It is used only to *detect* a brand
token in a hostname, never to allow or block by itself, and it is not a
security guarantee: a domain that survives the skeleton is not proven benign.
"""

from __future__ import annotations

import re
import unicodedata

CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ь": "b", "г": "r", "п": "n",
    # Greek lookalikes
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "ν": "v", "μ": "u", "χ": "x", "γ": "y",
    # Latin lookalikes and leetspeak digits
    "ł": "l", "ø": "o", "đ": "d", "ı": "i", "ſ": "s",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b", "9": "g",
}

DIGRAPH_MAP: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"))

MIN_ALIAS_LENGTH = 4


def skeleton(value: str) -> str:
    """Lowercase alphanumeric skeleton with confusables mapped to ASCII."""

    decomposed = unicodedata.normalize("NFKD", value)
    output: list[str] = []
    for character in decomposed.lower():
        if character in CONFUSABLE_MAP:
            output.append(CONFUSABLE_MAP[character])
            continue
        if unicodedata.combining(character):
            continue
        if character.isalnum():
            output.append(character)
    return "".join(output)


def skeleton_variants(value: str) -> set[str]:
    """Skeleton plus digraph-collapsed variants used for comparison only."""

    base = skeleton(value)
    variants = {base}
    for source, target in DIGRAPH_MAP:
        additions = {item.replace(source, target) for item in variants}
        variants |= additions
    return variants


def label_tokens(value: str) -> set[str]:
    """Token set for one hostname label or free-text fragment.

    Tokens are split on any non-alphanumeric character, so `paypal-secure`
    yields `{"paypal", "secure"}` and `applepie` yields `{"applepie"}`.
    """

    tokens: set[str] = set()
    for part in re.split(r"\W+", value.replace("_", " ")):
        for variant in skeleton_variants(part):
            if len(variant) >= MIN_ALIAS_LENGTH:
                tokens.add(variant)
    return tokens


def looks_confusable(value: str) -> bool:
    """True when the value contains non-ASCII or digit characters that the
    skeleton had to rewrite, i.e. the match depended on confusable handling."""

    for character in value.lower():
        if not character.isascii() or character.isdigit():
            return True
    return False


def idna_decode(label: str) -> str:
    """Best-effort punycode label decoding; returns the label unchanged on failure."""

    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return label
