"""Key-to-identity binding: trust-on-first-use pinning + impersonation reject."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_first_key_is_pinned_and_reported(client, signed_event):
    resp = client.post("/events", json=signed_event(sequence=1))
    assert resp.status_code == 201
    body = resp.json()
    assert body["signature_verified"] is True
    assert body["signer_identity"] == "primary-srv-01"  # agent_id fallback (no CN header)


def test_same_key_same_identity_is_accepted(client, signed_event):
    assert client.post("/events", json=signed_event(sequence=1)).status_code == 201
    assert client.post("/events", json=signed_event(sequence=2)).status_code == 201


def test_different_key_same_identity_is_rejected(client, signed_event):
    # First event pins the default key for "primary-srv-01".
    assert client.post("/events", json=signed_event(sequence=1)).status_code == 201
    # A second, different key claiming the same identity is impersonation.
    rogue = Ed25519PrivateKey.generate()
    resp = client.post("/events", json=signed_event(sequence=2, key=rogue))
    assert resp.status_code == 409
    assert "pinned" in resp.json()["detail"]


def test_same_key_two_identities_is_allowed(client, signed_event):
    # The same key under two different agent_ids pins two identities (both fine).
    assert client.post("/events", json=signed_event(agent_id="host-a", sequence=1)).status_code == 201
    assert client.post("/events", json=signed_event(agent_id="host-b", sequence=1)).status_code == 201


def test_mtls_cn_header_is_the_authoritative_identity(client, signed_event):
    # When a TLS edge forwards the verified CN, it overrides the JSON agent_id.
    ev = signed_event(sequence=1)
    resp = client.post("/events", json=ev, headers={"X-Client-Cert-CN": "primary-srv-01"})
    assert resp.status_code == 201
    assert resp.json()["signer_identity"] == "primary-srv-01"

    # A different key under the same CN is rejected even if it changes agent_id.
    rogue = Ed25519PrivateKey.generate()
    ev2 = signed_event(agent_id="spoofed", sequence=2, key=rogue)
    resp2 = client.post("/events", json=ev2, headers={"X-Client-Cert-CN": "primary-srv-01"})
    assert resp2.status_code == 409
