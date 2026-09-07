"""Receive-side Ed25519 verification + key-to-identity pinning in sentry/."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import signatures


# --- pure verifier ----------------------------------------------------------

def test_valid_signature_verifies(signed_event):
    ok, status, pub = signatures.verify_event_signature(signed_event())
    assert ok is True and status == signatures.VERIFIED and pub


# Every security-relevant field is inside the signed preimage, so tampering with
# any one of them must invalidate the signature (finding A: the "verified" flag
# must cover severity/category/detected_at/agent_sha256, not just 4 fields).
@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda ev: ev.update(raw_message=ev["raw_message"].replace("Failed", "Accepted")), id="raw_message"),
        pytest.param(lambda ev: ev.update(source="attacker/swapped"), id="source"),
        pytest.param(lambda ev: ev.update(event_type="ssh_login"), id="event_type"),
        pytest.param(lambda ev: ev.update(severity="info"), id="severity-downgrade"),
        pytest.param(lambda ev: ev.update(category=None), id="category-strip"),
        pytest.param(lambda ev: ev.update(category="x"), id="category-swap"),
        pytest.param(lambda ev: ev.update(detected_at="2000-01-01T00:00:00Z"), id="detected_at"),
        pytest.param(lambda ev: ev.update(occurred_at="2000-01-01T00:00:00Z"), id="occurred_at"),
        pytest.param(lambda ev: ev["payload"].update(agent_sha256="0" * 64), id="agent_sha256"),
    ],
)
def test_tampered_field_fails_verification(signed_event, mutate):
    ev = signed_event()
    mutate(ev)  # altered after signing
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


def test_ingest_rejects_category_strip(client, signed_event):
    # MITM strips `category` to suppress rule evaluation: the signature now
    # covers category, so the endpoint must reject it rather than store it
    # signature_verified=True (finding A).
    ev = signed_event()
    ev.pop("category")
    resp = client.post("/ingest", json=ev)
    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"]


def test_ingest_rejects_severity_downgrade(client, signed_event):
    ev = signed_event()
    ev["severity"] = "info"  # downgrade after signing
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
