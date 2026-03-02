"""
Encoding Utilities
==================

Decode various encoding evasion techniques used to bypass detection.
"""

import re
import base64
import logging
from typing import List

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for encoding detection
HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{1,3})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
URL_ENCODE_RE = re.compile(r"%([0-9a-fA-F]{2})")
BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def decode_hex_escapes(text: str) -> str:
    """Decode hex escape sequences like \\x63\\x75\\x72\\x6c -> curl."""
    def _replace(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return HEX_ESCAPE_RE.sub(_replace, text)


def decode_octal_escapes(text: str) -> str:
    """Decode octal escape sequences like \\143\\165\\162\\154 -> curl."""
    def _replace(match):
        try:
            value = int(match.group(1), 8)
            if value <= 0x10FFFF:
                return chr(value)
        except (ValueError, OverflowError):
            pass
        return match.group(0)
    return OCTAL_ESCAPE_RE.sub(_replace, text)


def decode_unicode_escapes(text: str) -> str:
    """Decode unicode escape sequences like \\u0063\\u0075\\u0072\\u006c -> curl."""
    def _replace(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return UNICODE_ESCAPE_RE.sub(_replace, text)


def decode_url_encoding(text: str) -> str:
    """Decode URL-encoded sequences like %63%75%72%6c -> curl."""
    def _replace(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return URL_ENCODE_RE.sub(_replace, text)


def decode_base64_payloads(text: str) -> str:
    """
    Detect and decode base64-encoded segments within text.

    Prepends decoded content before the original so both are scanned.
    Only decodes segments that produce valid UTF-8 text.
    """
    decoded_parts: List[str] = []
    for match in BASE64_RE.finditer(text):
        candidate = match.group(0)
        if len(candidate) < 8:
            continue
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="strict")
            if any(c.isalpha() for c in decoded):
                decoded_parts.append(decoded)
        except Exception:
            continue

    if decoded_parts:
        return " ".join(decoded_parts) + " " + text
    return text
