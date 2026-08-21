"""Hash-chain integrity + verification-script behaviour."""

from __future__ import annotations

import os


def _ingest(client, msg):
    return client.post(
        "/ingest",
        json={"event_type": "e", "source": "primary-01", "raw_message": msg, "payload": {}},
    )


def test_chain_links_across_records(client, modules):
    _, db = modules
    for i in range(3):
        assert _ingest(client, f"line {i}").status_code == 200

    conn = db.connect()
    try:
        rows = conn.execute("SELECT seq, prev_hash, row_hash FROM events ORDER BY seq").fetchall()
    finally:
        conn.close()

    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert rows[0]["prev_hash"] == "0" * 64
    assert rows[1]["prev_hash"] == rows[0]["row_hash"]
    assert rows[2]["prev_hash"] == rows[1]["row_hash"]


def test_verify_script_passes_then_detects_tamper(client, modules, monkeypatch):
    _, db = modules
    for i in range(3):
        _ingest(client, f"line {i}")

    import importlib
    from scripts import verify_chain

    importlib.reload(verify_chain)

    ok, message = verify_chain.verify(os.environ["SENTRY_DB_PATH"])
    assert ok is True
    assert message.startswith("[PASS] 3 records")

    # Tamper: mutate a plaintext column so recomputed hash diverges.
    conn = db.connect()
    try:
        conn.execute("UPDATE events SET severity='critical' WHERE seq=2")
        conn.commit()
    finally:
        conn.close()

    ok, message = verify_chain.verify(os.environ["SENTRY_DB_PATH"])
    assert ok is False
    assert "[FAIL]" in message and "seq 2" in message
