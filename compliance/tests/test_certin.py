"""CERT-In taxonomy + enrichment mapping."""

from __future__ import annotations

from barbarika_compliance import certin


def test_incident_types_are_the_official_twenty():
    ids = [cid for cid, _ in certin.INCIDENT_TYPES]
    assert len(certin.INCIDENT_TYPES) == 20
    assert ids[:5] == ["i", "ii", "iii", "iv", "v"]
    assert ids[-1] == "xx"


def test_category_label_maps_live_ids_to_official_wording():
    # The four live detection categories (iii/iv/v/x).
    assert certin.category_label("iii") == "Unauthorised access of IT systems/data"
    assert certin.category_label("iv") == "Defacement or intrusion into the website"
    assert certin.category_label("v") == "Malicious code attacks"
    assert certin.category_label("x") == "Attacks on Application such as E-Governance, E-Commerce etc."


def test_category_label_unknown_falls_back_safely():
    assert certin.category_label(None) == "Other (Please Specify)"
    assert certin.category_label("zz") == "Other (Please Specify)"


def test_category_numeral():
    assert certin.category_numeral("iii") == "Category (iii)"


def test_enrichment_has_mitre_and_vector_for_each_live_category():
    for cid in ("iii", "iv", "v", "x"):
        enr = certin.enrichment(cid)
        assert enr["mitre"], f"{cid} should carry MITRE techniques"
        assert isinstance(enr["mitre"], list)
        assert enr["attack_vector"].strip()


def test_enrichment_iii_is_bruteforce_base_without_hardcoded_sudo():
    enr = certin.enrichment("iii")
    mitre = " ".join(enr["mitre"])
    assert "T1110" in mitre        # brute force
    assert "T1078" in mitre        # valid accounts
    # Sudo escalation must NOT be hardcoded at the category level — the report layer
    # adds T1548.003 only when the evidence actually shows a sudo event.
    assert "T1548" not in mitre
    assert "sudo" not in str(enr["attack_vector"]).lower()


def test_enrichment_unknown_is_safe_default():
    enr = certin.enrichment("nope")
    assert enr["mitre"] == []
    assert enr["attack_vector"] == "Not classified."


def test_statutory_notice_cites_70b_and_six_hours():
    assert "70B" in certin.STATUTORY_NOTICE
    assert "6 hours" in certin.STATUTORY_NOTICE
    assert "28 April 2022" in certin.STATUTORY_NOTICE


def test_reporting_channel_is_the_official_certin_address():
    assert certin.REPORTING_CHANNEL["email"] == "incident@cert-in.org.in"
