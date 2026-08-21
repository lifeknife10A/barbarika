"""AES-GCM encryption-at-rest for event content + default masking of identifiers.

Two distinct protections (see sentry/README.md):

* **At rest:** the sensitive part of every event (raw_message + payload) is
  sealed with AES-GCM before it touches SQLite. The plaintext canonical bytes
  are hashed into the chain *before* sealing, and recovered by decrypting during
  verification — so encryption and tamper-evidence compose cleanly.
* **In responses:** identifiers (IPs, account names) are **masked by default**.
  Unmasking is an explicit, audited action, never the default.

Demo key handling: the master key comes from `SENTRY_MASTER_KEY` (base64, 32
bytes) if set, otherwise a local `sentry.key` file is generated with owner-only
permissions on first use. That file is git-ignored. This is demo-grade key
management, not an HSM/KMS — say so if asked.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_KEY_PATH = Path(__file__).resolve().parent.parent / "sentry.key"
_NONCE_LEN = 12


def _key_path() -> Path:
    return Path(os.environ.get("SENTRY_KEY_PATH", str(DEFAULT_KEY_PATH)))


def load_or_create_key() -> bytes:
    """Return the 32-byte AES key, generating/persisting a demo key if needed."""
    env = os.environ.get("SENTRY_MASTER_KEY")
    if env:
        key = base64.b64decode(env)
        if len(key) != 32:
            raise ValueError("SENTRY_MASTER_KEY must decode to 32 bytes")
        return key

    path = _key_path()
    if path.exists():
        return base64.b64decode(path.read_text().strip())

    key = secrets.token_bytes(32)
    old_umask = os.umask(0o077)
    try:
        path.write_text(base64.b64encode(key).decode("ascii"))
        os.chmod(path, 0o600)
    finally:
        os.umask(old_umask)
    return key


def seal(key: bytes, plaintext: bytes) -> bytes:
    """AES-GCM seal: returns nonce || ciphertext||tag."""
    nonce = secrets.token_bytes(_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def unseal(key: bytes, blob: bytes) -> bytes:
    """Inverse of seal(). Raises cryptography.exceptions.InvalidTag if tampered."""
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)


def seal_content(key: bytes, raw_message: str | None, payload: dict[str, Any]) -> bytes:
    body = json.dumps(
        {"raw_message": raw_message, "payload": payload},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return seal(key, body)


def unseal_content(key: bytes, blob: bytes) -> tuple[str | None, dict[str, Any]]:
    body = json.loads(unseal(key, blob).decode("utf-8"))
    return body.get("raw_message"), body.get("payload", {})


# --- masking (applied to responses by default) -----------------------------

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
# usernames after common auth-log keywords, e.g. "for admin", "user root".
_ACCOUNT = re.compile(r"\b(for|user)\s+(?:invalid user\s+)?([A-Za-z_][\w.-]*)")


def mask_text(text: str | None) -> str | None:
    """Redact IP addresses and account names from free text."""
    if text is None:
        return None
    text = _IPV4.sub("«ip»", text)
    text = _IPV6.sub("«ip»", text)
    text = _ACCOUNT.sub(lambda m: f"{m.group(1)} «account»", text)
    return text


_SENSITIVE_KEYS = {"src_ip", "ip", "dst_ip", "account", "username", "user", "email"}


def mask_payload(payload: dict[str, Any]) -> dict[str, Any]:
    masked: dict[str, Any] = {}
    for k, v in payload.items():
        if k.lower() in _SENSITIVE_KEYS:
            masked[k] = "«masked»"
        elif isinstance(v, str):
            masked[k] = mask_text(v)
        else:
            masked[k] = v
    return masked
