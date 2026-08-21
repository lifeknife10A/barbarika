"""Receive-side mTLS: enforce the client certificate, then resolve its identity.

Trust boundary reminder (AGENTS.md rule 3, transport/README): the agent's
identity is the **verified client-certificate identity**, never a JSON field.

Two layers, matching how mTLS is deployed in practice:

* **Enforcement** — `server_ssl_context()` / uvicorn `--ssl-cert-reqs 2`: TLS 1.3,
  client certificate REQUIRED, demo CA as the only trust anchor. A client with no
  cert (or one not signed by the demo CA) never completes the handshake, so it
  never reaches the app. Authentication is therefore guaranteed by transport.
* **Identity** — uvicorn does not expose the peer certificate to the ASGI scope,
  so the verified Common Name is read from a header set by the TLS-terminating
  edge (`X-Client-Cert-CN`, the nginx `ssl_client_s_dn_cn` pattern). The edge
  MUST strip any client-supplied copy of that header. With no edge in the direct
  demo, an authenticated (https) request without the header resolves to a generic
  verified identity — the connection is still mutually authenticated.

For local plaintext runs, `SENTRY_DEV_INSECURE=1` injects a labelled dev identity
so the API stays runnable/testable — never enable that on a real host.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from fastapi import HTTPException, Request

DEFAULT_CERT_DIR = Path(__file__).resolve().parent.parent.parent / "transport" / "certs"
DEV_IDENTITY = "dev-insecure-local"
MTLS_VERIFIED_IDENTITY = "mtls-client"  # authenticated by transport, CN not forwarded
DEFAULT_CN_HEADER = "x-client-cert-cn"


def cert_dir() -> Path:
    return Path(os.environ.get("SENTRY_CERT_DIR", str(DEFAULT_CERT_DIR)))


def server_ssl_context() -> ssl.SSLContext:
    """Build the mTLS server context: TLS 1.3, client cert REQUIRED, demo CA only."""
    d = cert_dir()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=d / "demo-server.crt", keyfile=d / "demo-server.key")
    ctx.load_verify_locations(cafile=d / "demo-ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def identity_from_peercert(peercert: dict | None) -> str | None:
    """Return the client-certificate CN (the authoritative agent identity)."""
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):  # subject is a tuple of RDN tuples
        for attr, value in rdn:
            if attr == "commonName":
                return value
    return None


def cn_header_name() -> str:
    return os.environ.get("SENTRY_CLIENT_CN_HEADER", DEFAULT_CN_HEADER).lower()


def require_client_identity(request: Request) -> str:
    """FastAPI dependency: the verified agent identity, or 401.

    Resolution order:
      1. `SENTRY_DEV_INSECURE=1` (local dev only) -> a labelled dev identity.
      2. forwarded verified-CN header from the mTLS edge -> that CN.
      3. request arrived over TLS (https) -> generic verified identity, because
         the transport already required + verified a demo-CA client certificate.
      4. otherwise (plaintext, not dev) -> 401.
    """
    if os.environ.get("SENTRY_DEV_INSECURE") == "1":
        return DEV_IDENTITY

    forwarded = request.headers.get(cn_header_name())
    if forwarded:
        return forwarded

    if request.url.scheme == "https":
        return MTLS_VERIFIED_IDENTITY

    raise HTTPException(status_code=401, detail="client certificate required")
