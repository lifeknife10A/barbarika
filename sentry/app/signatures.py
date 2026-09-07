"""Receive-side Ed25519 verification of agent-signed events.

The agent (agent/barbarika-agent) signs the canonical pipe-joined tuple

    event_type | source | severity | category | occurred_at | detected_at
                | raw_message | agent_sha256

with Ed25519 and ships ``agent_pubkey`` + ``agent_signature`` (both base64) in the
event ``payload``. Verification runs over the *raw* request JSON, because the
signature covers the exact wire ``occurred_at`` string (Go RFC3339Nano, nanosecond
precision) which a re-serialized ``datetime`` would not reproduce.

Every security-relevant field is authenticated: a man-in-the-middle cannot strip
``category`` (suppressing rule evaluation), downgrade ``severity``, or swap the
``agent_sha256`` provenance hash without invalidating the signature. The field
order and ``|`` separator MUST stay byte-for-byte identical to the signer
(agent/barbarika-agent/pkg/egress/mapping.go :: canonicalSignable).

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


def _s(value: Any) -> str:
    """Coerce a wire field to the exact string the signer used (None -> "")."""
    return "" if value is None else str(value)


def canonical_preimage(
    event_type: Any,
    source: Any,
    severity: Any,
    category: Any,
    occurred_at: Any,
    detected_at: Any,
    raw_message: Any,
    agent_sha256: Any,
) -> bytes:
    """Reproduce the exact bytes the agent signed (must match canonicalSignable).

    An absent ``category`` (omitted on the wire) and an absent ``agent_sha256``
    both collapse to the empty string, matching the Go side where a nil category
    pointer / empty hash serialize the same way.
    """
    return "|".join(
        (
            _s(event_type),
            _s(source),
            _s(severity),
            _s(category),
            _s(occurred_at),
            _s(detected_at),
            _s(raw_message),
            _s(agent_sha256),
        )
    ).encode("utf-8")


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
            raw["event_type"],
            raw["source"],
            raw.get("severity"),
            raw.get("category"),
            raw["occurred_at"],
            raw.get("detected_at"),
            raw["raw_message"],
            payload.get("agent_sha256"),
        )
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, preimage)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, INVALID, pubkey_b64

    return True, VERIFIED, pubkey_b64
