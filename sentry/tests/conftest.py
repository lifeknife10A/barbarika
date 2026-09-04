"""Shared fixtures: isolated DB + key per test, dev-insecure mTLS bypass."""

from __future__ import annotations

import base64
import importlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRY_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SENTRY_KEY_PATH", str(tmp_path / "test.key"))
    monkeypatch.setenv("SENTRY_DEV_INSECURE", "1")  # skip real client-cert check in unit tests
    return tmp_path


@pytest.fixture()
def modules(env):
    from app import crypto, db, detect, main

    for mod in (crypto, db, detect, main):
        importlib.reload(mod)
    return main, db


@pytest.fixture()
def client(modules):
    main, _ = modules
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def signed_event():
    """Build a validly agent-signed /ingest body.

    Mirrors agent/barbarika-agent: signs `event_type|source|occurred_at|
    raw_message` with Ed25519 and puts base64 pubkey+signature in payload. Pass a
    different `key` to simulate a second (rogue) signer for the same identity.
    """
    default_key = Ed25519PrivateKey.generate()

    def build(event_type="ssh_failed_login", source="primary-srv-01/auth",
              severity="warn", category="iii",
              occurred_at="2026-09-04T12:00:01.123456789Z",
              raw_message="sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
              key: Ed25519PrivateKey | None = None):
        k = key or default_key
        pub_b64 = base64.b64encode(k.public_key().public_bytes_raw()).decode("ascii")
        preimage = f"{event_type}|{source}|{occurred_at}|{raw_message}".encode()
        sig_b64 = base64.b64encode(k.sign(preimage)).decode("ascii")
        return {
            "event_type": event_type,
            "source": source,
            "severity": severity,
            "category": category,
            "occurred_at": occurred_at,
            "detected_at": occurred_at,
            "raw_message": raw_message,
            "payload": {
                "agent_id": "primary-srv-01",
                "agent_pubkey": pub_b64,
                "agent_signature": sig_b64,
            },
        }

    return build
