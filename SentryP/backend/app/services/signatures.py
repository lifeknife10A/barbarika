"""Receive-side Ed25519 verification of agent-signed events.

The agent (agent/barbarika-agent) signs the canonical pipe-joined tuple

    agent_id | sequence | timestamp | source | raw_content

with Ed25519 and ships ``agent_pubkey`` + ``agent_signature`` (both base64) in
the event ``payload``. Because the signature covers the *exact* timestamp string
on the wire (Go RFC3339Nano, nanosecond precision), verification must run against
the raw request JSON — a re-serialized ``datetime`` would not reproduce the same
bytes. See integration/CONTRACT.md.

This proves the event was not altered in transit and that the holder of the
presented key produced it. It does NOT by itself prove *which* agent, unless the
public key is pre-registered / bound to the verified mTLS client certificate —
that binding is a documented follow-up.
"""

from __future__ import annotations

import base64
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Verification outcomes.
VERIFIED = "verified"
UNSIGNED = "unsigned"
INVALID = "invalid"


def canonical_preimage(
    agent_id: str, sequence: int, timestamp: str, source: str, raw_content: str
) -> bytes:
    """Reproduce the exact bytes the agent signed (must match http_client.go)."""
    return f"{agent_id}|{sequence}|{timestamp}|{source}|{raw_content}".encode("utf-8")


def verify_event_signature(raw: Mapping[str, Any]) -> tuple[bool, str, str | None]:
    """Verify a raw ingest body's Ed25519 signature.

    Returns ``(verified, status, signer_pubkey_b64)`` where status is one of
    VERIFIED / UNSIGNED / INVALID. UNSIGNED means no signature was presented;
    INVALID means one was presented but did not verify (treat as tampering).
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
            str(raw["agent_id"]),
            int(raw["sequence"]),
            str(raw["timestamp"]),
            str(raw["source"]),
            str(payload.get("raw_content", "")),
        )
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, preimage)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, INVALID, pubkey_b64

    return True, VERIFIED, pubkey_b64
