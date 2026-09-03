"""Test fixtures: isolated temp DB + a helper that signs like the Go agent."""

from __future__ import annotations

import base64
import os
import tempfile

import pytest

# Point the app at a throwaway DB *before* the app package is imported.
_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="sentryp-test-"), "test.db")
os.environ["SENTRY_DB_PATH"] = _TMP_DB

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from backend.app.database import Base, engine
from backend.app.main import app


@pytest.fixture(autouse=True)
def _clean_db():
    """Fresh events + agent_keys per test so key pinning is isolated."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def signed_event():
    """Return a builder for a validly agent-signed event.

    Mirrors agent/barbarika-agent: signs `agent_id|sequence|timestamp|source|
    raw_content` with Ed25519 and puts base64 pubkey+signature in payload. Pass a
    different `key` to simulate a second (rogue) signer for the same identity.
    """
    default_key = Ed25519PrivateKey.generate()

    def build(agent_id="primary-srv-01", sequence=1,
              timestamp="2026-09-04T12:00:01.123456789Z",
              source="auth", raw_content="Failed password for root from 1.2.3.4",
              key: Ed25519PrivateKey | None = None):
        k = key or default_key
        pub_b64 = base64.b64encode(k.public_key().public_bytes_raw()).decode("ascii")
        preimage = f"{agent_id}|{sequence}|{timestamp}|{source}|{raw_content}".encode()
        sig_b64 = base64.b64encode(k.sign(preimage)).decode("ascii")
        return {
            "agent_id": agent_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "source": source,
            "event_type": "ssh_failed_login",
            "payload": {
                "raw_content": raw_content,
                "agent_pubkey": pub_b64,
                "agent_signature": sig_b64,
            },
        }

    return build
