"""Rule-integration: Category (iii) SSH brute-force fires an incident on ingest."""

from __future__ import annotations


def _post(client, msg, second):
    ts = f"2026-08-22T10:00:{second:02d}+00:00"
    return client.post(
        "/ingest",
        json={
            "event_type": "ssh_auth",
            "source": "primary-srv-01/auth.log",
            "category": "iii",
            "occurred_at": ts,
            "detected_at": ts,
            "raw_message": msg,
            "payload": {},
        },
    )


def test_bruteforce_then_success_records_one_incident(client):
    for i in range(10):
        assert _post(
            client,
            f"sshd[41{i:02d}]: Failed password for invalid user admin from 203.0.113.42 port 5100{i} ssh2",
            i * 5,
        ).status_code == 200
    # No incident yet from failures alone.
    assert client.get("/incidents").json() == []

    assert _post(
        client, "sshd[4199]: Accepted password for admin from 203.0.113.42 port 51099 ssh2", 55
    ).status_code == 200

    incidents = client.get("/incidents").json()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["category"] == "iii"
    assert len(inc["event_ids"]) == 11  # 10 failures + 1 success

    # Idempotent: re-evaluating does not duplicate the same incident.
    _post(client, "sshd[4200]: some benign line", 56)
    assert len(client.get("/incidents").json()) == 1


def test_reused_credential_does_not_over_fire(client):
    # 12 failed logins from one source, then THREE successful logins seconds apart:
    # the real brute-force success plus the Cat iv/v scripts re-authenticating with
    # the cracked password. The base rule must record exactly ONE incident, not one
    # per later login (the pre-fix behaviour that produced duplicate iii incidents).
    for i in range(12):
        assert _post(
            client,
            f"sshd[42{i:02d}]: Failed password for root from 192.168.29.176 port 600{i:02d} ssh2",
            i,
        ).status_code == 200
    for j, sec in enumerate((20, 23, 26)):
        assert _post(
            client,
            f"sshd[4300]: Accepted password for root from 192.168.29.176 port 700{j} ssh2",
            sec,
        ).status_code == 200

    incidents = client.get("/incidents").json()
    base = [i for i in incidents if i["rule_id"] == "9f97782e-878a-42f9-babe-f70ef18bc9c7"]
    assert len(base) == 1  # exactly one brute-force incident despite three reused logins


def test_benign_traffic_records_no_incident(client):
    for i in range(3):
        _post(client, f"sshd[7{i}]: Failed password for admin from 198.51.100.9 port 1{i} ssh2", i)
    assert client.get("/incidents").json() == []
    assert client.get("/health").json()["rules_loaded"] >= 1
