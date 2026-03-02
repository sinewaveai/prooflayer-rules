"""
Secret Masking
==============

Masks sensitive data in tool call arguments before writing to reports.
"""

import math
import re
from collections import Counter
from typing import Any, Dict

# Key name patterns that indicate sensitive values
_SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|passwd|token|api_key|apikey|secret|credential|auth|"
    r"private_key|access_key|session|cookie|authorization|bearer)",
    re.IGNORECASE,
)

_MASKED_VALUE = "***REDACTED***"

# Minimum length for high-entropy detection
_MIN_SECRET_LENGTH = 32


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_like_secret(value: str) -> bool:
    """Check if a string value looks like a secret (high entropy, long)."""
    if len(value) < _MIN_SECRET_LENGTH:
        return False
    return _shannon_entropy(value) > 4.0


def mask_sensitive_data(data: Dict[str, Any], _depth: int = 0) -> Dict[str, Any]:
    """
    Mask sensitive values in a dictionary.

    Detects sensitive keys by name pattern and high-entropy string values.
    Returns a new dictionary with sensitive values replaced by a redaction marker.

    Args:
        data: Dictionary of tool call arguments.
        _depth: Internal recursion depth counter.

    Returns:
        A new dictionary with sensitive values masked.
    """
    if _depth > 10:
        return data

    masked: Dict[str, Any] = {}
    for key, value in data.items():
        if _SENSITIVE_KEY_PATTERNS.search(key):
            masked[key] = _MASKED_VALUE
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_data(value, _depth + 1)
        elif isinstance(value, str) and _looks_like_secret(value):
            masked[key] = _MASKED_VALUE
        else:
            masked[key] = value

    return masked
