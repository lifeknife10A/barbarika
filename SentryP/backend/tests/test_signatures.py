"""Receive-side Ed25519 verification: unit + ingest-endpoint behaviour."""

from __future__ import annotations

from backend.app.services import signatures


# --- pure verifier ----------------------------------------------------------

def test_valid_signature_verifies(signed_event):
    ok, status, pub = signatures.verify_event_signature(signed_event())
    assert ok is True
    assert status == signatures.VERIFIED
    assert pub


def test_tampered_field_fails_verification(signed_event):
    ev = signed_event()
    ev["payload"]["raw_content"] = "Accepted password for admin from 1.2.3.4"  # altered
    ok, status, _ = signatures.verify_event_signature(ev)
    assert ok is False
    assert status == signatures.INVALID


def test_missing_signature_is_unsigned(signed_event):
    ev = signed_event()
    ev["payload"].pop("agent_signature")
    ok, status, _ = signatures.verify_event_signature(ev)
    assert ok is False
    assert status == signatures.UNSIGNED


# --- ingest endpoint --------------------------------------------------------

def test_ingest_marks_valid_signature_verified(client, signed_event):
    resp = client.post("/events", json=signed_event(sequence=1))
    assert resp.status_code == 201
    body = resp.json()
    assert body["signature_verified"] is True
    assert body["signer_pubkey"]


def test_ingest_rejects_tampered_signature(client, signed_event):
    ev = signed_event(sequence=2)
    ev["agent_id"] = "attacker-swapped-id"  # break the signed preimage
    resp = client.post("/events", json=ev)
    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"]


def test_ingest_accepts_unsigned_by_default(client, signed_event):
    ev = signed_event(sequence=3)
    ev["payload"].pop("agent_signature")
    ev["payload"].pop("agent_pubkey")
    resp = client.post("/events", json=ev)
    assert resp.status_code == 201
    assert resp.json()["signature_verified"] is False
