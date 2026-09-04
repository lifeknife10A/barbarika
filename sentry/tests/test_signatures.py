"""Receive-side Ed25519 verification + key-to-identity pinning in sentry/."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import signatures


# --- pure verifier ----------------------------------------------------------

def test_valid_signature_verifies(signed_event):
    ok, status, pub = signatures.verify_event_signature(signed_event())
    assert ok is True and status == signatures.VERIFIED and pub


def test_tampered_field_fails_verification(signed_event):
    ev = signed_event()
    ev["raw_message"] = ev["raw_message"].replace("Failed", "Accepted")  # altered after signing
    ok, status, _ = signatures.verify_event_signature(ev)
    assert ok is False and status == signatures.INVALID


def test_missing_signature_is_unsigned(signed_event):
    ev = signed_event()
    ev["payload"].pop("agent_signature")
    ok, status, _ = signatures.verify_event_signature(ev)
    assert ok is False and status == signatures.UNSIGNED


# --- ingest endpoint --------------------------------------------------------

def test_ingest_records_verified_and_pins_identity(client, signed_event):
    assert client.post("/ingest", json=signed_event()).status_code == 200
    ev = client.get("/events").json()[0]
    assert ev["signature_verified"] is True
    assert ev["signer_pubkey"] and ev["signer_identity"]


def test_ingest_rejects_tampered_signature(client, signed_event):
    ev = signed_event()
    ev["source"] = "attacker/swapped"  # break the signed preimage
    resp = client.post("/ingest", json=ev)
    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"]


def test_ingest_accepts_unsigned_by_default(client, signed_event):
    ev = signed_event()
    ev["payload"].pop("agent_signature")
    ev["payload"].pop("agent_pubkey")
    assert client.post("/ingest", json=ev).status_code == 200
    assert client.get("/events").json()[0]["signature_verified"] is False


def test_ingest_rejects_rogue_key_for_pinned_identity(client, signed_event):
    # First verified event pins the key for the (dev) identity.
    assert client.post("/ingest", json=signed_event()).status_code == 200
    # A different key claiming the same identity is impersonation.
    rogue = Ed25519PrivateKey.generate()
    resp = client.post("/ingest", json=signed_event(key=rogue))
    assert resp.status_code == 409
    assert "pinned" in resp.json()["detail"]
