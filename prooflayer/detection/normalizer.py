"""
Input Normalization and Decoding Layer
=======================================

Pre-processes input text before regex matching to defeat evasion techniques:
- Case normalization
- Unicode homoglyph normalization
- Encoding decoding (hex, octal, unicode, URL, base64)
- Whitespace normalization
- Nested object flattening
"""

import re
import base64
import logging
import unicodedata
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Mapping of common Unicode homoglyphs (Cyrillic and other lookalikes) to ASCII.
# This catches attackers substituting visually-similar characters to evade regex.
HOMOGLYPH_MAP = {
    # Cyrillic → Latin
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041d": "H",  # Н
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0455": "s",  # ѕ (Cyrillic small letter dze)
    "\u0456": "i",  # і (Cyrillic small letter byelorussian-ukrainian i)
    "\u0458": "j",  # ј
    "\u04bb": "h",  # һ
    "\u04c0": "l",  # Ӏ (Cyrillic letter palochka)
    # Greek → Latin
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a5": "Y",  # Υ
    "\u03a7": "X",  # Χ
    "\u03b1": "a",  # α (only when used as lookalike)
    "\u03bf": "o",  # ο
    # Fullwidth → ASCII
    "\uff21": "A",
    "\uff22": "B",
    "\uff23": "C",
    "\uff24": "D",
    "\uff25": "E",
    "\uff26": "F",
    "\uff27": "G",
    "\uff28": "H",
    "\uff29": "I",
    "\uff2a": "J",
    "\uff2b": "K",
    "\uff2c": "L",
    "\uff2d": "M",
    "\uff2e": "N",
    "\uff2f": "O",
    "\uff30": "P",
    "\uff31": "Q",
    "\uff32": "R",
    "\uff33": "S",
    "\uff34": "T",
    "\uff35": "U",
    "\uff36": "V",
    "\uff37": "W",
    "\uff38": "X",
    "\uff39": "Y",
    "\uff3a": "Z",
    "\uff41": "a",
    "\uff42": "b",
    "\uff43": "c",
    "\uff44": "d",
    "\uff45": "e",
    "\uff46": "f",
    "\uff47": "g",
    "\uff48": "h",
    "\uff49": "i",
    "\uff4a": "j",
    "\uff4b": "k",
    "\uff4c": "l",
    "\uff4d": "m",
    "\uff4e": "n",
    "\uff4f": "o",
    "\uff50": "p",
    "\uff51": "q",
    "\uff52": "r",
    "\uff53": "s",
    "\uff54": "t",
    "\uff55": "u",
    "\uff56": "v",
    "\uff57": "w",
    "\uff58": "x",
    "\uff59": "y",
    "\uff5a": "z",
}

# Import decode functions from encoding module (shared with utils.encoding)
from ..utils.encoding import (
    HEX_ESCAPE_RE as _HEX_ESCAPE_RE,
    OCTAL_ESCAPE_RE as _OCTAL_ESCAPE_RE,
    UNICODE_ESCAPE_RE as _UNICODE_ESCAPE_RE,
    URL_ENCODE_RE as _URL_ENCODE_RE,
    BASE64_RE as _BASE64_RE,
    decode_hex_escapes,
    decode_octal_escapes,
    decode_unicode_escapes,
    decode_url_encoding,
    decode_base64_payloads,
)

_WHITESPACE_RE = re.compile(r"[\s\t\n\r]+")

# Zero-width and bidirectional override characters to strip
_ZERO_WIDTH_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff"  # ZWS, ZWNJ, ZWJ, word joiner, BOM
    "\u202a\u202b\u202c\u202d\u202e"   # bidi overrides
    "]+"
)


def strip_zero_width(text: str) -> str:
    """Strip zero-width characters and bidi overrides."""
    return _ZERO_WIDTH_RE.sub("", text)


def normalize_path(text: str) -> str:
    """
    Normalize path-like sequences in text.

    Resolves /./  → /
    Resolves //   → /
    Strips trailing slashes from path-like segments.
    Does NOT resolve ../ (that changes semantics).
    """
    # Resolve /./  → /
    text = re.sub(r"/\./", "/", text)
    # Resolve //   → /  (but preserve protocol://)
    text = re.sub(r"(?<!:)//+", "/", text)
    # Strip trailing slashes from path-like segments (but not standalone /)
    text = re.sub(r"(/[a-zA-Z0-9._-]+)/+(?=\s|$)", r"\1", text)
    return text


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode homoglyphs to ASCII equivalents.

    Uses NFKD decomposition first (handles fullwidth, compatibility forms),
    then applies explicit homoglyph mapping for Cyrillic/Greek lookalikes.
    """
    # NFKD normalization decomposes compatibility characters
    text = unicodedata.normalize("NFKD", text)

    # Apply homoglyph mapping for characters that survive NFKD
    result = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[char])
        else:
            result.append(char)

    return "".join(result)


def normalize_whitespace(text: str) -> str:
    """Normalize tabs, newlines, and multiple spaces to single spaces."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def flatten_value(value: Any) -> List[str]:
    """
    Recursively extract all string values from nested dicts/lists.

    Instead of str() which produces Python repr format (e.g. "{'key': 'value'}"),
    this extracts the actual string values for proper pattern matching.
    """
    strings = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            strings.extend(flatten_value(v))
    elif isinstance(value, (list, tuple)):
        for item in value:
            strings.extend(flatten_value(item))
    elif value is not None:
        strings.append(str(value))
    return strings


def flatten_arguments(arguments: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Flatten all argument values, returning a mapping of param name
    to list of extracted string values.
    """
    result = {}
    for key, value in arguments.items():
        result[key] = flatten_value(value)
    return result


def normalize_text(text: str) -> str:
    """
    Apply the full normalization pipeline to a single text string.

    Order matters:
    1. Base64 decoding (FIRST — base64 is case-sensitive, must decode before lowering)
    2. Unicode homoglyph normalization (before lowering, to map correctly)
    3. Encoding decoding (hex, octal, unicode, URL)
    4. Case normalization (lowercase)
    5. Whitespace normalization
    """
    text = strip_zero_width(text)
    text = decode_base64_payloads(text)
    text = normalize_unicode(text)
    text = decode_hex_escapes(text)
    text = decode_octal_escapes(text)
    text = decode_unicode_escapes(text)
    text = decode_url_encoding(text)
    text = normalize_path(text)
    text = text.lower()
    text = normalize_whitespace(text)
    return text
