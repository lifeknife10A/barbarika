"""End-to-end report: interactive CERT-In form (page 1) + Detailed Incident Report
annexure. Default output is editable (form fields intact); flatten=True locks it."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pypdf import PdfReader

from barbarika_compliance import generate


def _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, *, flatten=False):
    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / ("report_final.pdf" if flatten else "report.pdf"))
    return generate.generate_report(
        db_path=seeded_vault["db"], submission_path=submission_toml,
        out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"], flatten=flatten)


def _text(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_report_has_form_and_annexure(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    pdf = Path(res["pdf"])
    assert pdf.exists() and pdf.stat().st_size > 3000
    assert len(PdfReader(str(pdf)).pages) >= 3  # form page + annexure pages


def test_default_report_is_editable(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    fields = PdfReader(res["pdf"]).get_fields()
    # Page 1 keeps its real, already-filled form fields so the engineer can edit.
    assert fields and len(fields) >= 40


def test_flatten_locks_the_report(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, flatten=True)
    reader = PdfReader(res["pdf"])
    assert not reader.get_fields()
    assert "/AcroForm" not in reader.trailer["/Root"]


def test_flattened_form_page_is_the_authentic_form_with_values(seeded_vault, submission_toml, tmp_path, monkeypatch):
    # Flattened -> field values are painted into the page and text-extractable.
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, flatten=True)
    page1 = PdfReader(res["pdf"]).pages[0].extract_text() or ""
    assert "Incident Reporting Form" in page1
    assert "It is not mandatory to fill" in page1          # printed on the real form
    assert "Electronics Niketan" in page1                  # printed footer
    assert "Unauthorised access of IT systems/data" in page1  # matched category label
    assert seeded_vault["reviewer"] in page1               # Name & Role/Title value
    # The affected-system IP is the VICTIM host (event source), never the attacker.
    assert seeded_vault["internal_host"] in page1          # IP Address value = victim host
    assert seeded_vault["attacker_ip"] not in page1        # attacker is an IOC, not the affected asset
    assert "Meridian FinServ" in page1                     # Organization name value


def test_annexure_has_full_ir_sections(seeded_vault, submission_toml, tmp_path, monkeypatch):
    # The annexure is reportlab (real page content), extractable in either mode.
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    text = _text(res["pdf"])
    for heading in (
        "Detailed Incident Report", "Executive summary", "Statutory basis",
        "Incident timeline", "Technical analysis", "Impact",
        "Indicators of compromise", "Evidence provenance", "evidence log", "Response",
    ):
        assert heading in text, f"missing section: {heading}"
    assert "SSH brute force" in text                        # fired rule title
    assert "chain intact" in text                           # integrity attestation
    assert seeded_vault["attacker_ip"] in text              # unmasked IOC
    assert res["audit_ref"] in text                         # audit reference
    assert "T1110.001" in text                              # MITRE technique


def test_tampered_vault_integrity_section_does_not_claim_chain_intact(
        seeded_vault, submission_toml, tmp_path, monkeypatch):
    # Mutate a hashed column so re-verification fails, then generate. The integrity
    # section must flag [FAIL] and must NOT assert "chain intact"/"0 tampering" —
    # that contradiction would misrepresent the evidence in a statutory document.
    conn = sqlite3.connect(seeded_vault["db"])
    conn.execute("UPDATE events SET severity = 'info' WHERE seq = 2")
    conn.commit()
    conn.close()
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, flatten=True)
    text = _text(res["pdf"])
    assert "[FAIL]" in text
    assert "seq 2" in text                       # the actual finding is surfaced
    assert "chain intact" not in text            # never asserted on a failed verify
    assert "0 tampering" not in text


def test_locked_pdf_metadata(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    meta = PdfReader(res["pdf"]).metadata
    assert meta.author == "Barbarika Compliance Engine"
    assert seeded_vault["incident_uuid"] in (meta.title or "")


def test_email_is_a_draft_never_sent(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    body = Path(res["email"]).read_text(encoding="utf-8")
    assert "DRAFT — NOT SENT" in body
    assert "incident@cert-in.org.in" in body
    assert seeded_vault["attacker_ip"] in body


def test_audit_ref_is_recorded(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    assert res["audit_ref"].startswith("AUD-")
    log = (tmp_path / "audit.log.jsonl").read_text(encoding="utf-8")
    assert res["audit_ref"] in log and seeded_vault["incident_uuid"] in log
