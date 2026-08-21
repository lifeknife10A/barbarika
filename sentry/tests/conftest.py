"""Shared fixtures: isolated DB + key per test, dev-insecure mTLS bypass."""

from __future__ import annotations

import importlib

import pytest
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
