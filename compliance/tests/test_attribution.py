"""IP attribution (victim vs attacker) and evidence-gated sudo wording.

These drive report.build_context directly with hand-built evidence, so both bugs
the demo run surfaced are pinned:
  Bug 1 — a same-LAN (RFC-1918) attacker must not land in the affected-system IP,
          and a private source IP must not be labelled 'external'.
  Bug 2 — the narrative may claim privileged sudo only when a sudo event exists.
"""

from __future__ import annotations

from barbarika_compliance import report
from barbarika_compliance.model import ChainAttestation, EventEvidence, IncidentRecord

BRUTEFORCE_RULE = "9f97782e-878a-42f9-babe-f70ef18bc9c7"


def _ev(seq, source, raw, event_type="ssh_auth_failure", payload=None):
    t = f"2026-09-09T00:00:{seq:02d}Z"
    return EventEvidence(
        id=seq, seq=seq, event_type=event_type, source=source, severity="warning",
        category="iii", occurred_at=t, detected_at=t, received_at=t,
        raw_message=raw, payload=payload or {}, row_hash="h", prev_hash="p",
        signature_verified=True, signer_identity=None, signer_pubkey=None,
    )


def _incident(events, rule_id=BRUTEFORCE_RULE,
              rule_title="SSH brute force followed by successful authentication"):
    return IncidentRecord(
        incident_uuid="11b6a538-0000-0000-0000-000000000000", rule_id=rule_id,
        rule_title=rule_title, category="iii", event_ids=[e.id for e in events],
        detected_at=events[0].detected_at, created_at=events[0].detected_at, events=events)


def _submission(ip_address="auto"):
    return {
        "incident": {"occurrence_override": "", "noticed_at": "auto", "confirmed_at": "",
                     "impact_summary": "Investigation ongoing.", "remediation": []},
        "affected_system": {"ip_address": ip_address, "domain_url": "host.example.in",
                            "operating_system": "Ubuntu 24.04", "application": "", "location": "",
                            "isp": "", "make_model_cloud": "", "mission_critical": "Yes",
                            "mission_critical_note": ""},
    }


def _ctx(events, ip_address="auto"):
    inc = _incident(events)
    chain = ChainAttestation(ok=True, records=len(events), message="[PASS]")
    return report.build_context(inc, _submission(ip_address), chain, "AUD-TEST")


# ---- Bug 1: attacker vs victim IP -------------------------------------------

def test_same_lan_attacker_is_not_the_affected_ip():
    # Kali on the same LAN; the agent host has no IP in the log text.
    evs = [
        _ev(1, "primary-srv-01/journald",
            "sshd[811]: Failed password for root from 192.168.29.176 port 51044 ssh2"),
        _ev(2, "primary-srv-01/journald",
            "sshd[822]: Accepted password for root from 192.168.29.176 port 51050 ssh2",
            event_type="ssh_auth_success"),
    ]
    ctx = _ctx(evs)
    assert "192.168.29.176" in ctx["ips"]              # it's the attacker source
    assert ctx["affected_ip"] != "192.168.29.176"      # NOT the affected asset
    assert ctx["affected_ip"] == ""                    # no victim IP in evidence -> blank


def test_victim_ip_comes_from_the_event_source_host():
    evs = [
        _ev(1, "10.0.4.12", "sshd: Failed password for admin from 185.220.101.4 port 4000 ssh2"),
        _ev(2, "10.0.4.12", "sshd: Accepted password for admin from 185.220.101.4 port 4090 ssh2",
            event_type="ssh_auth_success"),
    ]
    ctx = _ctx(evs)
    assert ctx["affected_ip"] == "10.0.4.12"           # victim host from source
    assert "185.220.101.4" in ctx["ips"]               # attacker still an IOC


def test_private_ip_is_not_labelled_external():
    assert report._is_private_ip("192.168.29.176")
    assert report._is_private_ip("10.0.4.12")
    assert report._is_private_ip("172.16.5.5")
    assert not report._is_private_ip("172.32.5.5")     # outside the 172.16/12 block
    assert not report._is_private_ip("185.220.101.4")  # public


# ---- Bug 2: sudo claim only when evidence shows it --------------------------

def test_no_sudo_event_means_no_sudo_claim():
    evs = [
        _ev(1, "10.0.4.12", "sshd: Failed password for admin from 185.220.101.4 port 4000 ssh2"),
        _ev(2, "10.0.4.12", "sshd: Accepted password for admin from 185.220.101.4 port 4090 ssh2",
            event_type="ssh_auth_success"),
    ]
    ctx = _ctx(evs)
    assert "sudo" not in ctx["attack_vector"].lower()
    assert not any("T1548" in t for t in ctx["mitre"])


def test_sudo_event_present_adds_the_escalation_claim():
    evs = [
        _ev(1, "10.0.4.12", "sshd: Accepted password for admin from 185.220.101.4 port 4090 ssh2",
            event_type="ssh_auth_success"),
        _ev(2, "10.0.4.12", "sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash",
            event_type="sudo_command"),
    ]
    ctx = _ctx(evs)
    assert "sudo" in ctx["attack_vector"].lower()
    assert any("T1548.003" in t for t in ctx["mitre"])
