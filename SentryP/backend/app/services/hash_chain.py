import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """Return a deterministic JSON representation (sorted keys, no spaces)."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

def to_utc_naive_iso(ts: Union[str, datetime]) -> str:
    """Canonical timestamp string used for hashing on BOTH ingest and verify.

    SQLite stores DateTime columns without timezone info, so a tz-aware value
    hashed at ingest ("...+00:00") would not match the naive value read back at
    verify time ("...") and every row would look tampered. Normalizing both
    sides to a UTC, tz-naive ISO string keeps ingest and verification in
    agreement regardless of the input timezone.
    """
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat()

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
