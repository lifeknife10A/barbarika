"""Consolidated multi-incident report: one form, many Incident Type boxes,
earliest-anchored timeline, merged evidence — without regressing the single path."""

from __future__ import annotations

from barbarika_compliance import acroform, certin, report
from barbarika_compliance.model import ChainAttestation, EventEvidence, IncidentRecord

PRIVESC_RULE = "afe8cbd2-7a70-4bbe-a7c2-2affe460db19"
BRUTE_RULE = "9f97782e-878a-42f9-babe-f70ef18bc9c7"


def _ev(seq, source, raw, event_type="log"):
    t = f"2026-09-09T00:{seq // 60:02d}:{seq % 60:02d}Z"
    return EventEvidence(
        id=seq, seq=seq, event_type=event_type, source=source, severity="warning",
        category=None, occurred_at=t, detected_at=t, received_at=t, raw_message=raw,
        payload={}, row_hash=f"h{seq}", prev_hash="p", signature_verified=True,
        signer_identity=None, signer_pubkey=None)


def _inc(uuid, rule_id, title, category, events):
    det = min(e.detected_at for e in events)
    return IncidentRecord(incident_uuid=uuid, rule_id=rule_id, rule_title=title,
                          category=category, event_ids=[e.seq for e in events],
                          detected_at=det, created_at=det, events=events)


def _submission(ip_address="auto"):
    return {
        "incident": {"occurrence_override": "", "noticed_at": "auto", "confirmed_at": "",
                     "impact_summary": "Investigation ongoing.", "remediation": ["Isolated host."]},
        "affected_system": {"ip_address": ip_address, "domain_url": "host.example.in",
                            "operating_system": "Ubuntu 24.04", "application": "nginx", "location": "",
                            "isp": "", "make_model_cloud": "", "mission_critical": "Yes",
                            "mission_critical_note": ""},
        "reporter": {"name_role": "Priya Shah, CISO", "organization_name": "Meridian",
                     "i_am": "the effected entity", "kind": "Organization", "contact_no": "1",
                     "email": "a@b.in", "address": "X"},
        "affected_entity": {"same_as_reporter": True, "name": ""},
        "reviewer": {"name": "Priya Shah", "role": "CISO"},
    }


# Five real attacks from one session; the base-iii events are a subset of the
# privesc-iii incident (shared SSH failures), and the victim host is 10.0.4.12.
def _session_incidents():
    ssh = [_ev(s, "10.0.4.12", f"sshd: Failed password for root from 192.168.29.176 port {4000+s} ssh2")
           for s in range(1, 13)]
    ok = _ev(13, "10.0.4.12", "sshd: Accepted password for root from 192.168.29.176 port 4099 ssh2",
             event_type="ssh_auth_success")
    sudo = _ev(14, "10.0.4.12", "sudo: root : TTY=pts/0 ; COMMAND=/bin/bash", event_type="sudo_command")
    web = _ev(20, "10.0.4.12", "nginx: GET /.env HTTP/1.1 200 -> write /var/www/html/x.php", event_type="http")
    ranswrite = _ev(30, "10.0.4.12", "kernel: mass rewrite under /srv/data; canary .canary_token.docx altered")
    appatk = _ev(40, "10.0.4.12", "nginx: GET /shop?id=1 UNION SELECT u,p FROM users-- 500 (sqlmap)", event_type="http")
    return [
        _inc("2016a469-iii-base", BRUTE_RULE, "SSH brute force followed by successful authentication",
             "iii", ssh + [ok]),
        _inc("73b9f110-iii-priv", PRIVESC_RULE, "SSH brute force, successful auth, then privileged sudo",
             "iii", ssh + [ok, sudo]),
        _inc("bf1c8470-iv", "iv-rule", "Website defacement / intrusion", "iv", [web]),
        _inc("af4415de-v", "v-rule", "Ransomware / malicious code burst", "v", [ranswrite]),
        _inc("0f5d7c53-x", "x-rule", "Application-layer attack", "x", [appatk]),
    ]


def _ctx():
    incs = _session_incidents()
    chain = ChainAttestation(ok=True, records=99, message="[PASS]")
    return report.build_combined_context(incs, _submission(), chain, "AUD-X")


def test_redundant_base_iii_is_folded_into_privesc():
    ctx = _ctx()
    uuids = [i.incident_uuid for i in ctx["incidents"]]
    assert "2016a469-iii-base" not in uuids       # subset of privesc -> dropped
    assert "73b9f110-iii-priv" in uuids
    assert len(ctx["incidents"]) == 4             # iii(priv), iv, v, x


def test_all_contributing_categories_present_and_ordered():
    ctx = _ctx()
    assert ctx["combined"] is True
    assert ctx["categories"] == ["iii", "iv", "v", "x"]   # first-seen order


def test_every_category_checkbox_is_ticked():
    ctx = _ctx()
    fields = acroform.build_field_values(ctx)
    for c in ("iii", "iv", "v", "x"):
        assert fields[acroform.CATEGORY_FIELD[c]] is True
    # A non-contributing category stays unticked; 'Other' is off.
    assert fields[acroform.CATEGORY_FIELD["vii"]] is False
    assert fields["incident_category_other"] is False


def test_timeline_anchored_to_earliest_noticed():
    ctx = _ctx()
    # earliest detected_at across all incidents is the first SSH failure (seq 1).
    assert ctx["detection"].endswith("00:00:01Z") or "00:00:01" in ctx["detection"]
    assert ctx["noticed"] == ctx["detection"]     # 6-hour clock starts at the first thing noticed


def test_merged_evidence_is_deduped_and_sorted():
    ctx = _ctx()
    seqs = [e.seq for e in ctx["incident"].events]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))            # no duplicate SSH events
    assert {1, 13, 14, 20, 30, 40} <= set(seqs)   # union across all attacks


def test_victim_ip_not_attacker_and_sudo_gated_true():
    ctx = _ctx()
    assert ctx["affected_ip"] == "10.0.4.12"      # Bug-1 fix preserved (victim, not attacker)
    assert "192.168.29.176" not in ctx["affected_ip"]
    # sudo evidence IS present here (privesc), so the claim + T1548.003 appear.
    assert "sudo" in ctx["attack_vector"].lower()
    assert any("T1548.003" in t for t in ctx["mitre"])


def test_iocs_deduped_across_incidents():
    ctx = _ctx()
    assert ctx["ips"].count("192.168.29.176") == 1  # appears in many incidents, listed once


def test_single_incident_list_falls_back_to_single_layout():
    incs = _session_incidents()[1:2]              # just the privesc incident
    chain = ChainAttestation(ok=True, records=14, message="[PASS]")
    ctx = report.build_combined_context(incs, _submission(), chain, "AUD-X")
    assert ctx["combined"] is False               # one incident -> single path
    assert ctx["cid"] == "iii"
