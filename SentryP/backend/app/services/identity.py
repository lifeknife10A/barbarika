"""Bind an agent's signing key to an identity (trust-on-first-use pinning).

Receive-side signature verification (services/signatures.py) proves that the
*presented* key signed the event. This module proves it is the *expected* key
for the identity:

* the identity is the verified mTLS client-certificate CN when a TLS edge
  forwards it (``X-Client-Cert-CN``) — authoritative — otherwise the event's
  ``agent_id`` (demo fallback, already gated by the mTLS transport);
* the first verified key seen for an identity is pinned; a later event for that
  identity presenting a *different* key is rejected (impersonation / key swap).

Binding results:
  BOUND_NEW   first key for this identity (just pinned)
  BOUND_MATCH presented key matches the pinned key
  MISMATCH    a different key is already pinned for this identity  -> reject
"""

from __future__ import annotations

import os

from sqlalchemy.orm import Session

from .. import models

BOUND_NEW = "bound-new"
BOUND_MATCH = "bound-match"
MISMATCH = "mismatch"


def cn_header_name() -> str:
    return os.environ.get("SENTRY_CLIENT_CN_HEADER", "x-client-cert-cn").lower()


def resolve_identity(cn_header: str | None, agent_id: str) -> str:
    """Authoritative mTLS CN if present, else the app-level agent_id."""
    cn = (cn_header or "").strip()
    return cn if cn else agent_id


def bind_key(db: Session, identity: str, pubkey: str) -> tuple[bool, str]:
    """Pin identity->pubkey (TOFU) and enforce it.

    Returns (ok, status). ok is False only on MISMATCH.
    """
    pinned = db.query(models.AgentKey).filter(models.AgentKey.identity == identity).first()
    if pinned is None:
        db.add(models.AgentKey(identity=identity, pubkey=pubkey))
        db.commit()
        return True, BOUND_NEW
    if pinned.pubkey == pubkey:
        return True, BOUND_MATCH
    return False, MISMATCH
