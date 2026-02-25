"""
Entropy Calculation
===================

Shannon entropy for detecting encoded/encrypted payloads.
"""

import math
from collections import Counter
from typing import Union


def calculate_shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate Shannon entropy of data.

    High entropy (> 4.5) suggests encoded/encrypted data, which could be
    an attempt to bypass pattern matching.

    Args:
        data: String or bytes to analyze

    Returns:
        Shannon entropy value (0.0 to 8.0 for bytes, 0.0 to ~5.0 for text)

    Example:
        >>> calculate_shannon_entropy("aaaaaaa")
        0.0
        >>> calculate_shannon_entropy("abcdefg")
        2.807
        >>> calculate_shannon_entropy("4r8Kq2!@#")  # High entropy
        3.251
    """
    if not data:
        return 0.0

    # Convert to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Count frequency of each byte
    counter = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
