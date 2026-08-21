"""Hash-chain verification for the Sentry evidence vault.

Reads every event in sequence order, decrypts its sealed content, recomputes the
domain-separated SHA-256 chain, and checks:

  * sequence numbers are contiguous starting at 1;
  * each row's prev_hash matches the prior row's row_hash;
  * each recomputed row_hash matches what is stored.

Prints `[PASS] N records | contiguous sequence | chain intact` on success, or a
`[FAIL] ...` line naming the first broken invariant. Chain-only: this does NOT
verify Ed25519 signatures (those are agent-side and not asserted here).

Usage:
    uv run python scripts/verify_chain.py [--db PATH]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import crypto, db, hashchain  # noqa: E402


def verify(db_path: str | None = None) -> tuple[bool, str]:
    if db_path:
        os.environ["SENTRY_DB_PATH"] = db_path
    key = crypto.load_or_create_key()
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT seq, received_at, sealed_blob, prev_hash, row_hash, "
            "event_type, source, severity, category, occurred_at, detected_at "
            "FROM events ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()

    expected_prev = hashchain.GENESIS_PREV_HASH
    for i, row in enumerate(rows, start=1):
        if row["seq"] != i:
            return False, f"[FAIL] non-contiguous sequence at position {i}: seq={row['seq']}"
        if row["prev_hash"] != expected_prev:
            return False, f"[FAIL] broken link at seq {row['seq']}: prev_hash mismatch"

        raw_message, payload = crypto.unseal_content(key, row["sealed_blob"])
        logical = {
            "event_type": row["event_type"],
            "source": row["source"],
            "severity": row["severity"],
            "category": row["category"],
            "occurred_at": row["occurred_at"],
            "detected_at": row["detected_at"],
            "raw_message": raw_message,
            "payload": payload,
        }
        recomputed = hashchain.compute_row_hash(
            prev_hash=row["prev_hash"],
            seq=row["seq"],
            received_at=row["received_at"],
            event_bytes=hashchain.canonical_bytes(logical),
        )
        if recomputed != row["row_hash"]:
            return False, f"[FAIL] tampered row at seq {row['seq']}: row_hash mismatch"
        expected_prev = row["row_hash"]

    return True, f"[PASS] {len(rows)} records | contiguous sequence | chain intact"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the Sentry hash chain.")
    parser.add_argument("--db", default=None, help="Path to sentry.db (default: env/SENTRY_DB_PATH).")
    args = parser.parse_args()
    ok, message = verify(args.db)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
