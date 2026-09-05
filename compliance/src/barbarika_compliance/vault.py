"""Read-only access to the Sentry evidence vault + INDEPENDENT chain re-verification.

Reuses Sentry's own canonical primitives (app.crypto + app.hashchain), imported
at runtime via sys.path, so the AES-GCM unseal and the SHA-256 chain formula can
never drift from what wrote the vault. The re-verification loop mirrors
sentry/scripts/verify_chain.py exactly. The vault is opened read-only.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

from .model import ChainAttestation, EventEvidence, IncidentRecord


def _import_sentry():
    """Import Sentry's crypto + hashchain from the sibling sentry/ tree."""
    repo = Path(__file__).resolve().parents[3]  # compliance/src/barbarika_compliance -> repo root
    sentry = repo / "sentry"
    if str(sentry) not in sys.path:
        sys.path.insert(0, str(sentry))
    from app import crypto, hashchain  # noqa: E402
    return crypto, hashchain


def load_key(key_path: str | None = None, master_key_b64: str | None = None) -> bytes:
    crypto, _ = _import_sentry()
    if master_key_b64:
        os.environ["SENTRY_MASTER_KEY"] = master_key_b64
    if key_path:
        os.environ["SENTRY_KEY_PATH"] = str(key_path)
    return crypto.load_or_create_key()


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def reverify_chain(conn: sqlite3.Connection, key: bytes) -> ChainAttestation:
    """Independently recompute the whole hash chain from the sealed rows."""
    crypto, hashchain = _import_sentry()
    rows = conn.execute(
        "SELECT seq, received_at, sealed_blob, prev_hash, row_hash, event_type, "
        "source, severity, category, occurred_at, detected_at, signature_verified "
        "FROM events ORDER BY seq ASC"
    ).fetchall()

    expected_prev = hashchain.GENESIS_PREV_HASH
    sig_ok = 0
    for i, row in enumerate(rows, start=1):
        if row["seq"] != i:
            return ChainAttestation(False, len(rows), f"[FAIL] non-contiguous sequence at position {i}")
        if row["prev_hash"] != expected_prev:
            return ChainAttestation(False, len(rows), f"[FAIL] broken link at seq {row['seq']}: prev_hash mismatch")
        raw_message, payload = crypto.unseal_content(key, row["sealed_blob"])
        logical = {
            "event_type": row["event_type"], "source": row["source"],
            "severity": row["severity"], "category": row["category"],
            "occurred_at": row["occurred_at"], "detected_at": row["detected_at"],
            "raw_message": raw_message, "payload": payload,
        }
        recomputed = hashchain.compute_row_hash(
            prev_hash=row["prev_hash"], seq=row["seq"],
            received_at=row["received_at"], event_bytes=hashchain.canonical_bytes(logical),
        )
        if recomputed != row["row_hash"]:
            return ChainAttestation(False, len(rows), f"[FAIL] tampered row at seq {row['seq']}: row_hash mismatch")
        expected_prev = row["row_hash"]
        if row["signature_verified"]:
            sig_ok += 1

    return ChainAttestation(
        ok=True, records=len(rows),
        message=f"[PASS] {len(rows)} records | contiguous sequence | chain intact",
        genesis=hashchain.GENESIS_PREV_HASH,
        domain_sep=hashchain.DOMAIN_SEP.decode("latin-1").rstrip("\x00"),
        signatures_verified=sig_ok, signatures_total=len(rows),
    )


def find_incident_row(conn: sqlite3.Connection, incident: str | None) -> sqlite3.Row | None:
    if not incident or incident == "latest":
        return conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
    return conn.execute("SELECT * FROM incidents WHERE incident_uuid = ?", (incident,)).fetchone()


def load_incident(conn: sqlite3.Connection, key: bytes, incident: str | None) -> IncidentRecord:
    """Load an incident + its correlated events with UNMASKED evidence."""
    crypto, _ = _import_sentry()
    inc = find_incident_row(conn, incident)
    if inc is None:
        raise LookupError(f"incident not found: {incident!r}")
    event_ids = json.loads(inc["event_ids_json"])
    events: list[EventEvidence] = []
    for eid in event_ids:
        r = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()
        if r is None:
            continue
        raw_message, payload = crypto.unseal_content(key, r["sealed_blob"])
        events.append(EventEvidence(
            id=r["id"], seq=r["seq"], event_type=r["event_type"], source=r["source"],
            severity=r["severity"], category=r["category"], occurred_at=r["occurred_at"],
            detected_at=r["detected_at"], received_at=r["received_at"],
            raw_message=raw_message, payload=payload, row_hash=r["row_hash"],
            prev_hash=r["prev_hash"], signature_verified=bool(r["signature_verified"]),
            signer_identity=r["signer_identity"], signer_pubkey=r["signer_pubkey"],
        ))
    events.sort(key=lambda e: e.seq)
    return IncidentRecord(
        incident_uuid=inc["incident_uuid"], rule_id=inc["rule_id"],
        rule_title=inc["rule_title"], category=inc["category"],
        event_ids=event_ids, detected_at=inc["detected_at"],
        created_at=inc["created_at"], events=events,
    )
