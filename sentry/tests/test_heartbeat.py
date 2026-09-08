"""Receive-side heartbeat + dead-man's-switch watchdog.

HTTP tests exercise POST /heartbeat and GET /watchdog through the app; the
time-based liveness transitions are unit-tested against WatchdogManager with an
injected clock (the state machine takes monotonic time explicitly).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _make_heartbeat(key: Ed25519PrivateKey, *, agent_id="primary-srv-01",
                    seq=0, last_event_sequence=0, last_event_hash="0" * 64):
    """Build a wire heartbeat body + base64 public key exactly as the Go agent does,
    using the shared transport HeartbeatGenerator (signs the canonical preimage)."""
    import heartbeat as T  # transport module; path injected by app.watchdog import

    gen = T.HeartbeatGenerator(
        agent_id=agent_id, boot_id=UUID(int=1),
        signer=lambda b: key.sign(b), next_sequence=seq,
    )
    payload = gen.generate(
        sent_at_utc=datetime.now(timezone.utc),
        last_event_sequence=last_event_sequence,
        last_event_hash=last_event_hash,
    )
    pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    return payload.to_mapping(), pub_b64


# --- HTTP endpoint behaviour ------------------------------------------------

def test_signed_heartbeat_is_accepted_and_listed(client):
    from app import watchdog  # noqa: F401 — ensures transport path is injected
    key = Ed25519PrivateKey.generate()
    body, pub = _make_heartbeat(key)

    r = client.post("/heartbeat", json=body, headers={"X-Public-Key": pub})
    assert r.status_code == 202, r.text
    ack = r.json()
    assert ack["signature_verified"] is True
    assert ack["state"] == "HEALTHY"
    assert ack["agent_id"] == "primary-srv-01"

    w = client.get("/watchdog")
    assert w.status_code == 200
    rows = w.json()
    assert len(rows) == 1
    assert rows[0]["state"] == "HEALTHY"
    assert rows[0]["signature_verified"] is True


def test_tampered_signature_is_rejected(client):
    from app import watchdog  # noqa: F401
    key = Ed25519PrivateKey.generate()
    body, pub = _make_heartbeat(key)
    # Alter a signed field after signing -> preimage no longer matches -> 400.
    body["last_event_hash"] = "f" * 64
    r = client.post("/heartbeat", json=body, headers={"X-Public-Key": pub})
    assert r.status_code == 400
    assert "signature" in r.json()["detail"]


def test_malformed_payload_is_422(client):
    key = Ed25519PrivateKey.generate()
    body, pub = _make_heartbeat(key)
    body.pop("agent_health")  # violates the shared schema
    r = client.post("/heartbeat", json=body, headers={"X-Public-Key": pub})
    assert r.status_code == 422


def test_unsigned_heartbeat_rejected_in_strict_mode(client, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "REQUIRE_SIGNATURE", True)
    key = Ed25519PrivateKey.generate()
    body, _pub = _make_heartbeat(key)
    r = client.post("/heartbeat", json=body)  # no X-Public-Key -> unsigned
    assert r.status_code == 401


# --- watchdog liveness transitions (injected clock) -------------------------

def _payload():
    import heartbeat as T
    key = Ed25519PrivateKey.generate()
    gen = T.HeartbeatGenerator(agent_id="primary-srv-01", boot_id=UUID(int=1),
                               signer=lambda b: key.sign(b))
    return gen.generate(sent_at_utc=datetime.now(timezone.utc),
                        last_event_sequence=0, last_event_hash="0" * 64)


def test_healthy_within_window():
    from app import watchdog as W
    mgr = W.WatchdogManager()
    t0 = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    mgr.record("agent-a", _payload(), signature_verified=True, now_monotonic=0.0, now_utc=t0)
    snap = mgr.snapshot(now_monotonic=5.0, now_utc=t0 + timedelta(seconds=5))
    assert snap[0]["state"] == "HEALTHY"
    assert snap[0]["requires_human_confirmation"] is False


def test_telemetry_loss_without_intrusion_is_operational_warning():
    from app import watchdog as W
    mgr = W.WatchdogManager()
    t0 = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    mgr.record("agent-a", _payload(), signature_verified=True, now_monotonic=0.0, now_utc=t0)
    loss = t0 + timedelta(seconds=16)
    snap = mgr.snapshot(now_monotonic=16.0, now_utc=loss, latest_intrusion_utc=None)
    assert snap[0]["state"] == "TELEMETRY_LOSS"
    assert snap[0]["disposition"] == "OPERATIONAL_WARNING"
    assert snap[0]["requires_human_confirmation"] is False


def test_telemetry_loss_after_intrusion_is_candidate_category_ii():
    from app import watchdog as W
    mgr = W.WatchdogManager()
    t0 = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    mgr.record("agent-a", _payload(), signature_verified=True, now_monotonic=0.0, now_utc=t0)
    loss = t0 + timedelta(seconds=16)
    intrusion = loss - timedelta(seconds=30)  # within the 120s window
    snap = mgr.snapshot(now_monotonic=16.0, now_utc=loss, latest_intrusion_utc=intrusion)
    row = snap[0]
    assert row["state"] == "TELEMETRY_LOSS"
    assert row["disposition"] == "CANDIDATE_CATEGORY_II_REVIEW_REQUIRED"
    assert row["requires_human_confirmation"] is True
    assert "Category (ii)" in row["statutory_category"]
    assert row["proposed_noticed_at_utc"] == loss


def test_poll_transitions_reports_a_change_once():
    from app import watchdog as W
    mgr = W.WatchdogManager()
    t0 = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    mgr.record("agent-a", _payload(), signature_verified=True, now_monotonic=0.0, now_utc=t0)
    loss = t0 + timedelta(seconds=16)
    first = mgr.poll_transitions(now_monotonic=16.0, now_utc=loss)
    assert len(first) == 1 and first[0]["state"] == "TELEMETRY_LOSS"
    # No further change reported on the next poll at the same state.
    again = mgr.poll_transitions(now_monotonic=17.0, now_utc=loss + timedelta(seconds=1))
    assert again == []
