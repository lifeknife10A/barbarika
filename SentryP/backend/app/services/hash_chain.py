import hashlib
import json
from typing import Any, Dict, Optional

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """Return a deterministic JSON representation (sorted keys, no spaces)."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

def compute_hash(prev_hash: Optional[str], timestamp: str, event_data: Dict[str, Any]) -> str:
    """Compute SHA-256 hash for a new event.

    Args:
        prev_hash: Hex string of the previous event hash (or empty string for first).
        timestamp: ISO-8601 string, UTC.
        event_data: The event payload dictionary (excluding hash fields).
    Returns:
        Hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()
    hasher.update((prev_hash or "").encode("utf-8"))
    hasher.update(timestamp.encode("utf-8"))
    hasher.update(_canonical_json(event_data))
    return hasher.hexdigest()
