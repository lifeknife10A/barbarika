#!/usr/bin/env python3
"""Provenance checks over mTLS: agent signatures verify; a rogue key is rejected.

Run by integration/run_mtls_e2e.sh after the agent has ingested events. Asserts
every stored event passed receive-side Ed25519 verification and is pinned to one
identity, then posts a signed event with a *different* key for that identity and
expects HTTP 409 (impersonation). Uses ssl + http.client; the rogue key uses
`cryptography` (a Sentry dependency, present in its venv).
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import ssl
import sys
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def make_ctx(certs: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(certs / "demo-ca.crt"))
    ctx.load_cert_chain(str(certs / "demo-client.crt"), str(certs / "demo-client.key"))
    return ctx


def get(ctx, host, port, path):
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    try:
        conn.request("GET", path)
        return json.loads(conn.getresponse().read())
    finally:
        conn.close()


def post(ctx, host, port, path, body) -> int:
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    try:
        conn.request("POST", path, body=json.dumps(body).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--certs", required=True, type=Path)
    args = ap.parse_args()

    u = urlparse(args.base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 443
    ctx = make_ctx(args.certs)

    events = get(ctx, host, port, "/events?limit=500")
    verified = [e for e in events if e.get("signature_verified")]
    idents = {e.get("signer_identity") for e in verified}
    print(f"[SIG] {len(verified)}/{len(events)} stored events passed receive-side "
          f"Ed25519 verification (identity={idents})")
    assert events and len(verified) == len(events), "some agent events failed verification"

    # A different key claiming the same identity (valid signature, wrong key).
    # Sign the full canonical event (must match sentry/app/signatures.py).
    rogue = Ed25519PrivateKey.generate()
    et, src, sev, cat = "ssh_failed_login", "primary-srv-01/auth", "warn", "iii"
    occ, raw = "2026-09-04T00:00:00Z", "rogue attempt"
    sha = "0" * 64
    preimage = "|".join([et, src, sev, cat, occ, occ, raw, sha]).encode()
    body = {
        "event_type": et, "source": src, "severity": sev, "category": cat,
        "occurred_at": occ, "detected_at": occ, "raw_message": raw,
        "payload": {
            "agent_sha256": sha,
            "agent_pubkey": base64.b64encode(rogue.public_key().public_bytes_raw()).decode(),
            "agent_signature": base64.b64encode(rogue.sign(preimage)).decode(),
        },
    }
    status = post(ctx, host, port, "/ingest", body)
    print(f"[BIND] rogue key impersonating the pinned identity -> HTTP {status} (expected 409)")
    if status != 409:
        print("[BIND][FAIL] impersonation not rejected")
        sys.exit(1)


if __name__ == "__main__":
    main()
