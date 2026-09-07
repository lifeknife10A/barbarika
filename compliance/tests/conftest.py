"""Shared fixtures: a fully seeded Sentry evidence vault built with Sentry's own
storage layer (real AES-GCM sealing + real hash chain), so the compliance layer's
independent re-verification is tested against genuine, not fabricated, data.
"""

from __future__ import annotations

import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# compliance/tests -> compliance -> repo root
REPO = Path(__file__).resolve().parents[2]
SENTRY = REPO / "sentry"

ATTACKER_IP = "185.220.101.4"
INTERNAL_HOST = "10.0.4.12"
RULE_ID = "9f97782e-878a-42f9-babe-f70ef18bc9c7"  # category_iii_ssh_bruteforce.yaml
RULE_TITLE = "SSH brute force followed by successful authentication"
INCIDENT_UUID = "2049917b-aaaa-bbbb-cccc-000000000001"
REVIEWER = "Priya Shah"


def _sentry_modules():
    if str(SENTRY) not in sys.path:
        sys.path.insert(0, str(SENTRY))
    from app import crypto, db  # noqa: WPS433

    return crypto, db


@pytest.fixture
def seeded_vault(tmp_path, monkeypatch):
    """Build a real vault (13 events, one category-iii incident) and return its
    paths plus the ground-truth values a report/verification test can assert."""
    key_path = tmp_path / "vault.key"
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("SENTRY_KEY_PATH", str(key_path))
    monkeypatch.setenv("SENTRY_DB_PATH", str(db_path))
    monkeypatch.delenv("SENTRY_MASTER_KEY", raising=False)

    crypto, db = _sentry_modules()
    key = crypto.load_or_create_key()
    db.init_db()
    conn = db.connect()

    base = datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)
    event_ids: list[int] = []

    # 12 failed SSH auths from the same external source in a tight window...
    for i in range(12):
        t = base + timedelta(seconds=i * 3)
        res = db.append_event(
            conn, key,
            event_type="ssh_auth_failure", source=INTERNAL_HOST,
            severity="warning", category="iii",
            occurred_at=t, detected_at=t, received_at=t,
            raw_message=(f"sshd[2211]: Failed password for admin from "
                         f"{ATTACKER_IP} port {4000 + i} ssh2"),
            payload={"src_ip": ATTACKER_IP, "user": "admin"},
            signature_verified=True, signer_identity="agent@sentry",
            signer_pubkey="ed25519:demo-pub",
        )
        event_ids.append(res["id"])

    # ...followed by a successful authentication from that same source.
    t = base + timedelta(seconds=40)
    res = db.append_event(
        conn, key,
        event_type="ssh_auth_success", source=INTERNAL_HOST,
        severity="critical", category="iii",
        occurred_at=t, detected_at=t, received_at=t,
        raw_message=(f"sshd[2299]: Accepted password for admin from "
                     f"{ATTACKER_IP} port 4090 ssh2"),
        payload={"src_ip": ATTACKER_IP, "user": "admin"},
        signature_verified=True, signer_identity="agent@sentry",
        signer_pubkey="ed25519:demo-pub",
    )
    event_ids.append(res["id"])

    # The receive path stamps signature provenance columns (now native to the
    # Sentry schema); the seeding above sets them so the compliance reader
    # exercises the same shape as production.
    detected_iso = (base + timedelta(seconds=40)).isoformat()
    db.record_incident(
        conn,
        incident_uuid=INCIDENT_UUID, rule_id=RULE_ID, rule_title=RULE_TITLE,
        category="iii", event_ids_json=json.dumps(event_ids),
        detected_at=detected_iso, created_at=detected_iso,
        signature="sig-" + secrets.token_hex(8),
    )
    conn.commit()
    # Flush WAL into the main db file so a read-only opener sees every row.
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()

    return {
        "db": str(db_path), "key": str(key_path),
        "attacker_ip": ATTACKER_IP, "internal_host": INTERNAL_HOST,
        "incident_uuid": INCIDENT_UUID, "rule_id": RULE_ID,
        "rule_title": RULE_TITLE, "n_events": 13, "reviewer": REVIEWER,
    }


@pytest.fixture
def submission_toml(tmp_path):
    """A complete, valid submission config written to disk (returns its path)."""
    p = tmp_path / "submission.toml"
    p.write_text(
        '[reporter]\n'
        'i_am = "the effected entity"\n'
        'name_role = "Priya Shah, Chief Information Security Officer"\n'
        'kind = "Organization"\n'
        'organization_name = "Meridian FinServ Pvt. Ltd."\n'
        'contact_no = "+91-22-4000-1200"\n'
        'email = "ciso@meridianfinserv.in"\n'
        'address = "Andheri East, Mumbai 400093, India"\n'
        '\n[affected_entity]\n'
        'same_as_reporter = true\n'
        '\n[affected_system]\n'
        'domain_url = "portal.meridianfinserv.in"\n'
        'ip_address = "auto"\n'
        'operating_system = "Ubuntu 24.04 LTS (Linux 6.8)"\n'
        'application = "Nginx 1.24 + internal e-commerce API"\n'
        'location = "Mumbai, India"\n'
        'mission_critical = "Yes"\n'
        'mission_critical_note = "Primary production host."\n'
        '\n[incident]\n'
        'noticed_at = "auto"\n'
        'impact_summary = "Unauthorised privileged access; investigation ongoing."\n'
        'remediation = ["Isolated the host.", "Rotated credentials."]\n'
        '\n[reviewer]\n'
        'name = "Priya Shah"\n'
        'role = "Chief Information Security Officer"\n'
        '\n[recipients]\n'
        'to = "incident@cert-in.org.in"\n'
        'cc = "soc@meridianfinserv.in"\n',
        encoding="utf-8",
    )
    return str(p)
