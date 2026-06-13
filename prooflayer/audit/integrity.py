"""Integrity helpers for audit chain-of-custody records."""

import hashlib
import json
from typing import Any, Dict, Optional


def canonical_json(payload: Dict[str, Any]) -> str:
    """Serialize a payload deterministically for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def chain_hash(payload: Dict[str, Any], previous_hash: Optional[str] = None) -> str:
    """Return a sha256 hash linking payload content to the previous hash."""
    material = {
        "payload": payload,
        "previous_hash": previous_hash or "",
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
