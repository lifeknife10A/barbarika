"""SQLite (WAL) storage — the single authoritative evidence store.

Per sentry/README.md there is no NDJSON/SQLite dual-write: SQLite is the one
source of truth. This module owns:

* the append-only, hash-chained `events` table (content sealed with AES-GCM);
* the derived `incidents` table written when a detection rule fires.

Non-sensitive columns (type, source, severity, category, timestamps, chain
fields) stay in plaintext so we can index, group for rule evaluation, and verify
the chain. The sensitive part (raw_message + payload) lives only inside
`sealed_blob`.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import crypto, hashchain

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "sentry.db"

# Serialize the read-prev -> compute-hash -> insert critical section so the chain
# stays contiguous under concurrent writers (single-process demo server).
_append_lock = threading.Lock()


def db_path() -> Path:
    return Path(os.environ.get("SENTRY_DB_PATH", str(DEFAULT_DB_PATH)))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seq          INTEGER NOT NULL UNIQUE,
    event_type   TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'info',
    category     TEXT,
    occurred_at  TEXT,
    detected_at  TEXT,
    received_at  TEXT    NOT NULL,
    sealed_blob  BLOB    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    row_hash     TEXT    NOT NULL,
    -- Receive-side Ed25519 verification result (metadata; NOT part of the chain
    -- preimage — the signature itself is inside sealed_blob and already chained).
    signature_verified INTEGER NOT NULL DEFAULT 0,
    signer_identity    TEXT,
    signer_pubkey      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_type        ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_category    ON events(category);

-- Pinned public key per agent identity (trust-on-first-use). The first verified
-- key seen for an identity is pinned; a later event for that identity presenting
-- a different key is rejected (impersonation / key swap).
CREATE TABLE IF NOT EXISTS agent_keys (
    identity   TEXT PRIMARY KEY,
    pubkey     TEXT NOT NULL,
    first_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uuid     TEXT    NOT NULL UNIQUE,
    rule_id           TEXT    NOT NULL,
    rule_title        TEXT    NOT NULL,
    category          TEXT    NOT NULL,
    event_ids_json    TEXT    NOT NULL,
    detected_at       TEXT    NOT NULL,
    created_at        TEXT    NOT NULL,
    signature         TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
"""


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt is not None else None


def append_event(
    conn: sqlite3.Connection,
    key: bytes,
    *,
    event_type: str,
    source: str,
    severity: str,
    category: str | None,
    occurred_at: datetime | None,
    detected_at: datetime | None,
    received_at: datetime,
    raw_message: str | None,
    payload: dict[str, Any],
    signature_verified: bool = False,
    signer_identity: str | None = None,
    signer_pubkey: str | None = None,
) -> dict[str, Any]:
    """Seal content, extend the hash chain, and insert one event row.

    Returns a dict with id, seq, received_at, row_hash. Thread-safe: the whole
    read-prev/compute/insert sequence runs under a process-wide lock. The
    signature_* metadata is stored alongside but is NOT part of the chain preimage.
    """
    received_iso = _iso(received_at)
    assert received_iso is not None

    # Canonical plaintext bytes are hashed BEFORE sealing, so verification can
    # decrypt and recompute the same digest.
    logical = {
        "event_type": event_type,
        "source": source,
        "severity": severity,
        "category": category,
        "occurred_at": _iso(occurred_at),
        "detected_at": _iso(detected_at),
        "raw_message": raw_message,
        "payload": payload,
    }
    event_bytes = hashchain.canonical_bytes(logical)
    sealed = crypto.seal_content(key, raw_message, payload)

    with _append_lock:
        prev = conn.execute("SELECT seq, row_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = 1 if prev is None else int(prev["seq"]) + 1
        prev_hash = hashchain.GENESIS_PREV_HASH if prev is None else prev["row_hash"]
        row_hash = hashchain.compute_row_hash(
            prev_hash=prev_hash, seq=seq, received_at=received_iso, event_bytes=event_bytes
        )
        cur = conn.execute(
            """
            INSERT INTO events
                (seq, event_type, source, severity, category,
                 occurred_at, detected_at, received_at, sealed_blob, prev_hash, row_hash,
                 signature_verified, signer_identity, signer_pubkey)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq, event_type, source, severity, category,
                _iso(occurred_at), _iso(detected_at), received_iso,
                sealed, prev_hash, row_hash,
                1 if signature_verified else 0, signer_identity, signer_pubkey,
            ),
        )
        conn.commit()
        event_id = int(cur.lastrowid)

    return {
        "id": event_id,
        "seq": seq,
        "received_at": received_at,
        "row_hash": row_hash,
    }


def bind_key(conn: sqlite3.Connection, identity: str, pubkey: str) -> tuple[bool, str]:
    """Pin identity->pubkey (trust-on-first-use) and enforce it.

    Returns (ok, status): ("bound-new" | "bound-match", True) or ("mismatch", False).
    """
    with _append_lock:
        row = conn.execute(
            "SELECT pubkey FROM agent_keys WHERE identity = ?", (identity,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO agent_keys (identity, pubkey, first_seen) VALUES (?, ?, ?)",
                (identity, pubkey, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return True, "bound-new"
        if row["pubkey"] == pubkey:
            return True, "bound-match"
        return False, "mismatch"


def record_incident(
    conn: sqlite3.Connection,
    *,
    incident_uuid: str,
    rule_id: str,
    rule_title: str,
    category: str,
    event_ids_json: str,
    detected_at: str,
    created_at: str,
    signature: str,
) -> bool:
    """Insert an incident. Returns False if it already existed (dedup)."""
    try:
        conn.execute(
            """
            INSERT INTO incidents
                (incident_uuid, rule_id, rule_title, category,
                 event_ids_json, detected_at, created_at, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (incident_uuid, rule_id, rule_title, category,
             event_ids_json, detected_at, created_at, signature),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def count_events(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def recent_events(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
    )[::-1]


def get_event(conn: sqlite3.Connection, event_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()


def list_incidents(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    )
