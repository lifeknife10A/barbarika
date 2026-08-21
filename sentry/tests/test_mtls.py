"""mTLS identity extraction + server context. Enforcement is via uvicorn TLS."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from app import mtls

CERT_DIR = Path(__file__).resolve().parent.parent.parent / "transport" / "certs"


def test_identity_from_peercert_reads_common_name():
    peercert = {"subject": ((("commonName", "primary-srv-01"),),)}
    assert mtls.identity_from_peercert(peercert) == "primary-srv-01"


def test_identity_from_missing_cert_is_none():
    assert mtls.identity_from_peercert(None) is None
    assert mtls.identity_from_peercert({}) is None


@pytest.mark.skipif(
    not (CERT_DIR / "demo-server.crt").exists(),
    reason="demo certs not generated (run transport/scripts/generate_demo_certs.sh)",
)
def test_server_ssl_context_requires_client_cert_and_tls13(monkeypatch):
    monkeypatch.setenv("SENTRY_CERT_DIR", str(CERT_DIR))
    ctx = mtls.server_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def _request(scheme: str, headers: list[tuple[bytes, bytes]] | None = None):
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "scheme": scheme,
            "headers": headers or [],
            "server": ("t", 80),
            "path": "/",
            "query_string": b"",
        }
    )


def test_plaintext_without_cert_is_rejected(monkeypatch):
    monkeypatch.delenv("SENTRY_DEV_INSECURE", raising=False)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        mtls.require_client_identity(_request("http"))
    assert exc.value.status_code == 401


def test_https_connection_is_transport_authenticated(monkeypatch):
    monkeypatch.delenv("SENTRY_DEV_INSECURE", raising=False)
    # https means the TLS layer already required+verified a demo-CA client cert.
    assert mtls.require_client_identity(_request("https")) == mtls.MTLS_VERIFIED_IDENTITY


def test_forwarded_cn_header_becomes_identity(monkeypatch):
    monkeypatch.delenv("SENTRY_DEV_INSECURE", raising=False)
    req = _request("https", [(b"x-client-cert-cn", b"primary-srv-01")])
    assert mtls.require_client_identity(req) == "primary-srv-01"


def test_dev_insecure_returns_labelled_identity(monkeypatch):
    monkeypatch.setenv("SENTRY_DEV_INSECURE", "1")
    assert mtls.require_client_identity(_request("http")) == mtls.DEV_IDENTITY
