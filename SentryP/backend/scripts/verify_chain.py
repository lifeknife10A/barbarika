"""Hash‑chain verification utility for the Barbarika Sentry.

Running this script walks the persisted ``Event`` rows in chronological order
and recomputes each record's SHA‑256 hash using the same algorithm that the
ingestion endpoint applies. If any record has been tampered with, the script
prints a clear failure message indicating the offending row; otherwise it
reports a clean verification.

Typical usage (from the repository root)::

    $ python -m backend.scripts.verify_chain

or, if you prefer the concrete script path::

    $ python backend/scripts/verify_chain.py

The script is deliberately self‑contained – it only depends on the local
SQLAlchemy models and the ``hash_chain`` service, both of which live inside the
``backend`` package.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

# Import the package‑internal components – the ``backend`` package is on the
# Python path because this file lives within it.
from backend.app import models, services
from backend.app.database import SessionLocal


def _load_events(session: Session) -> List[models.Event]:
    """Return all events ordered by ``agent_id`` then by ``sequence``.

    Ordering by ``agent_id`` ensures that each agent's chain is verified
    independently. ``sequence`` provides the deterministic order within a
    single agent.
    """
    stmt = session.query(models.Event).order_by(models.Event.agent_id, models.Event.sequence)
    return list(stmt)


def verify_chain(events: List[models.Event]) -> Tuple[bool, List[str]]:
    """Verify the hash chain.

    Args:
        events: List of ``Event`` objects already sorted by agent & sequence.

    Returns:
        (is_valid, messages) – ``is_valid`` is ``True`` when no tampering is
        detected. ``messages`` contains a human‑readable summary for each
        failure (or an empty list on success).
    """
    messages: List[str] = []
    # Track the most recent hash for each agent independently.
    prev_hash_by_agent: Dict[str, str] = defaultdict(str)

    for ev in events:
        # Build the dictionary that mirrors the ingestion payload (excluding the
        # hash fields). The timestamp must be the ISO‑8601 string used when the
        # event was originally stored.
        event_dict = {
            "agent_id": ev.agent_id,
            "sequence": ev.sequence,
            "timestamp": ev.timestamp.isoformat(),
            "source": ev.source,
            "event_type": ev.event_type,
            "payload": ev.payload,
        }
        expected = services.hash_chain.compute_hash(
            prev_hash_by_agent[ev.agent_id], ev.timestamp.isoformat(), event_dict
        )
        if expected != ev.cur_hash:
            messages.append(
                f"[FAIL] Agent {ev.agent_id} seq {ev.sequence}: hash mismatch\n"
                f"       Expected {expected[:12]}..., got {ev.cur_hash[:12]}..."
            )
        # Update the running hash for the next record of the same agent.
        prev_hash_by_agent[ev.agent_id] = ev.cur_hash

    return (len(messages) == 0, messages)


def main() -> None:
    # Create a single scoped session – the script is short‑lived.
    with SessionLocal() as session:
        events = _load_events(session)
        if not events:
            print("[INFO] No events stored – nothing to verify.")
            sys.exit(0)

        valid, msgs = verify_chain(events)
        if valid:
            print(f"[PASS] {len(events)} records verified, 0 tampering detected")
        else:
            print(f"[FAIL] {len(msgs)} tampering issue(s) detected:")
            for m in msgs:
                print(m)
            sys.exit(1)


if __name__ == "__main__":
    main()
