"""End-to-end proof: ingest -> sealed, hash-chained SQLite write -> masked read."""

from __future__ import annotations


def test_ingest_writes_chained_wal_row(client, modules):
    _, db = modules
    resp = client.post(
        "/ingest",
        json={
            "event_type": "ssh_auth_failure",
            "source": "primary-01/auth.log",
            "severity": "warn",
            "raw_message": "sshd[1]: Failed password for admin from 203.0.113.7 port 22 ssh2",
            "payload": {"src_ip": "203.0.113.7", "attempts": 12},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["id"] == 1 and body["seq"] == 1
    assert len(body["row_hash"]) == 64

    conn = db.connect()
    try:
        assert db.count_events(conn) == 1
        row = conn.execute("SELECT * FROM events WHERE id=1").fetchone()
        assert row["event_type"] == "ssh_auth_failure"
        assert row["prev_hash"] == "0" * 64
        # sensitive content is sealed, never stored in plaintext columns.
        assert b"203.0.113.7" not in bytes(row["sealed_blob"])
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_events_are_masked_by_default(client):
    client.post(
        "/ingest",
        json={
            "event_type": "ssh_auth_failure",
            "source": "primary-01/auth.log",
            "raw_message": "Failed password for admin from 203.0.113.7",
            "payload": {"src_ip": "203.0.113.7"},
        },
    )
    events = client.get("/events").json()
    assert events[0]["masked"] is True
    assert "203.0.113.7" not in events[0]["raw_message"]
    assert events[0]["payload"]["src_ip"] == "«masked»"


def test_unmask_requires_audit_token(client, monkeypatch):
    client.post(
        "/ingest",
        json={"event_type": "x", "source": "s", "raw_message": "ip 203.0.113.7", "payload": {}},
    )
    # No token configured -> unmask forbidden.
    assert client.get("/events/1", params={"unmask": True}).status_code == 403

    monkeypatch.setenv("SENTRY_UNMASK_TOKEN", "s3cret")
    ok = client.get("/events/1", params={"unmask": True}, headers={"X-Unmask-Token": "s3cret"})
    assert ok.status_code == 200
    assert ok.json()["masked"] is False
    assert "203.0.113.7" in ok.json()["raw_message"]


def test_ingest_rejects_missing_fields(client):
    assert client.post("/ingest", json={"source": "x"}).status_code == 422


def test_ingest_rejects_unknown_category(client):
    resp = client.post(
        "/ingest", json={"event_type": "x", "source": "s", "category": "zz"}
    )
    assert resp.status_code == 422
