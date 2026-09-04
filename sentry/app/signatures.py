"""Receive-side Ed25519 verification of agent-signed events.

The agent (agent/barbarika-agent) signs the canonical pipe-joined tuple

    event_type | source | occurred_at | raw_message

with Ed25519 and ships ``agent_pubkey`` + ``agent_signature`` (both base64) in the
event ``payload``. Verification runs over the *raw* request JSON, because the
signature covers the exact wire ``occurred_at`` string (Go RFC3339Nano, nanosecond
precision) which a re-serialized ``datetime`` would not reproduce.

This proves the event was not altered in transit and that the holder of the
presented key produced it. Binding *which* agent a key belongs to is handled by
``identity`` pinning (see app/db.py :: bind_key).
"""

from __future__ import annotations

import base64
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERIFIED = "verified"
UNSIGNED = "unsigned"
INVALID = "invalid"


def canonical_preimage(
    event_type: str, source: str, occurred_at: str, raw_message: str
) -> bytes:
    """Reproduce the exact bytes the agent signed (must match http_client.go)."""
    return f"{event_type}|{source}|{occurred_at}|{raw_message}".encode("utf-8")


def verify_event_signature(raw: Mapping[str, Any]) -> tuple[bool, str, str | None]:
    """Verify a raw ingest body's Ed25519 signature.

    Returns ``(verified, status, signer_pubkey_b64)`` where status is
    VERIFIED / UNSIGNED / INVALID. UNSIGNED = no signature presented; INVALID = a
    signature was presented but did not verify (treat as tampering).
    """
    payload = raw.get("payload") or {}
    pubkey_b64 = payload.get("agent_pubkey")
    sig_b64 = payload.get("agent_signature")
    if not pubkey_b64 or not sig_b64:
        return False, UNSIGNED, None

    try:
        pub_bytes = base64.b64decode(pubkey_b64)
        sig_bytes = base64.b64decode(sig_b64)
        preimage = canonical_preimage(
            str(raw["event_type"]),
            str(raw["source"]),
            str(raw["occurred_at"]),
            str(raw["raw_message"]),
        )
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, preimage)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, INVALID, pubkey_b64

    return True, VERIFIED, pubkey_b64
