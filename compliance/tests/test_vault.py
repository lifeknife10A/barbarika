"""Independent vault re-verification, unsealing, and parity with verify_chain.py."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from barbarika_compliance import vault

SENTRY = Path(__file__).resolve().parents[2] / "sentry"


def test_reverify_intact_chain_passes(seeded_vault):
    key = vault.load_key(key_path=seeded_vault["key"])
    conn = vault.connect(seeded_vault["db"])
    try:
        att = vault.reverify_chain(conn, key)
    finally:
        conn.close()
    assert att.ok is True
    assert att.records == seeded_vault["n_events"]
    assert "[PASS]" in att.message
    assert "chain intact" in att.message
    # Signature provenance is surfaced from the receive-side columns.
    assert att.signatures_verified == seeded_vault["n_events"]
    assert att.signatures_total == seeded_vault["n_events"]
    assert att.genesis == "0" * 64


def test_load_incident_returns_unmasked_evidence(seeded_vault):
    key = vault.load_key(key_path=seeded_vault["key"])
    conn = vault.connect(seeded_vault["db"])
    try:
        inc = vault.load_incident(conn, key, "latest")
    finally:
        conn.close()
    assert inc.incident_uuid == seeded_vault["incident_uuid"]
    assert inc.category == "iii"
    assert inc.rule_id == seeded_vault["rule_id"]
    assert len(inc.events) == seeded_vault["n_events"]
    # Events are seq-ordered and the raw log is UNMASKED (real IP, not «ip»).
    seqs = [e.seq for e in inc.events]
    assert seqs == sorted(seqs)
    joined = " ".join(e.raw_message or "" for e in inc.events)
    assert seeded_vault["attacker_ip"] in joined
    assert "«ip»" not in joined
    # Payload is unsealed too.
    assert inc.events[0].payload.get("src_ip") == seeded_vault["attacker_ip"]
    assert inc.events[0].signature_verified is True


def test_tampered_row_is_detected(seeded_vault):
    # Mutate a hashed plaintext column (severity) directly in the DB.
    conn = sqlite3.connect(seeded_vault["db"])
    conn.execute("UPDATE events SET severity = 'info' WHERE seq = 2")
    conn.commit()
    conn.close()

    key = vault.load_key(key_path=seeded_vault["key"])
    ro = vault.connect(seeded_vault["db"])
    try:
        att = vault.reverify_chain(ro, key)
    finally:
        ro.close()
    assert att.ok is False
    assert "seq 2" in att.message
    assert "[FAIL]" in att.message


def test_parity_with_sentry_verify_chain_script(seeded_vault):
    """The compliance re-verification message must equal Sentry's own tool."""
    env = dict(os.environ)
    env["SENTRY_KEY_PATH"] = seeded_vault["key"]
    env.pop("SENTRY_MASTER_KEY", None)
    proc = subprocess.run(
        [sys.executable, str(SENTRY / "scripts" / "verify_chain.py"),
         "--db", seeded_vault["db"]],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    script_msg = proc.stdout.strip()

    key = vault.load_key(key_path=seeded_vault["key"])
    conn = vault.connect(seeded_vault["db"])
    try:
        att = vault.reverify_chain(conn, key)
    finally:
        conn.close()

    assert script_msg == att.message
    assert script_msg == f"[PASS] {seeded_vault['n_events']} records | contiguous sequence | chain intact"
