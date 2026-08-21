"""Append-only, domain-separated SHA-256 hash chain over stored events.

Guarantee (see AGENTS.md rule 4 / sentry README): this is tamper-*evidence*,
not WORM and not forward secrecy. Any event already acknowledged by Sentry and
folded into the chain cannot be silently altered or dropped without breaking the
chain. If the Sentry host itself is compromised, the guarantee does not hold.

Chain formula (from sentry/README.md):

    row_hash = SHA-256( DomainSeparator || PrevHash || Sequence || ReceivedAt || ExactEventBytes )

`ExactEventBytes` is the canonical JSON of the logical event (see canonical_bytes).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Domain separator keeps these digests from colliding with any other SHA-256 use.
DOMAIN_SEP = b"barbarika.sentry.evidence.v1\x00"

# prev_hash for the very first record (seq == 1).
GENESIS_PREV_HASH = "0" * 64


def canonical_bytes(logical_event: dict[str, Any]) -> bytes:
    """Deterministic byte representation of a logical event ("ExactEventBytes").

    Sorted keys + compact separators so the same logical event always hashes to
    the same value regardless of dict ordering.
    """
    return json.dumps(
        logical_event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_row_hash(
    *, prev_hash: str, seq: int, received_at: str, event_bytes: bytes
) -> str:
    """Return the hex SHA-256 digest for one chain row."""
    h = hashlib.sha256()
    h.update(DOMAIN_SEP)
    h.update(prev_hash.encode("ascii"))
    h.update(str(seq).encode("ascii"))
    h.update(received_at.encode("utf-8"))
    h.update(event_bytes)
    return h.hexdigest()
