"""End-to-end report: fill the form's DOCX -> LibreOffice PDF -> stamp X marks ->
append the Detailed Incident Report annexure. Render-dependent tests skip when
LibreOffice cannot convert (e.g. CI without libreoffice-writer)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pypdf import PdfReader

from barbarika_compliance import generate


def _generate(seeded_vault, submission_toml, tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / "report.pdf")
    try:
        return generate.generate_report(
            db_path=seeded_vault["db"], submission_path=submission_toml,
            out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"],
        )
    except RuntimeError as exc:  # LibreOffice/Writer not available in this env
        pytest.skip(f"LibreOffice cannot render the form here: {exc}")


def _text(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_pdf_is_produced_with_form_and_annexure(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    pdf = Path(res["pdf"])
    assert pdf.exists() and pdf.stat().st_size > 3000
    # >= 1 form page (LibreOffice) + the annexure pages.
    assert len(PdfReader(str(pdf)).pages) >= 3


def test_pdf_is_flat_no_acroform(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    reader = PdfReader(res["pdf"])
    assert not reader.get_fields()
    assert "/AcroForm" not in reader.trailer["/Root"]


def test_form_is_the_authentic_government_form(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    text = _text(res["pdf"])
    # Text that only exists on the real CERT-In form.
    assert "Incident Reporting Form" in text
    assert "It is not mandatory to fill" in text
    assert "Electronics Niketan" in text
    # Our values were filled into the form's cells.
    assert seeded_vault["reviewer"] in text            # Name & Role/Title
    assert seeded_vault["attacker_ip"] in text         # IP Address
    assert "Meridian FinServ" in text                  # Organization name


def test_pdf_text_carries_the_statutory_essentials(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    text = _text(res["pdf"])
    assert "Unauthorised access of IT systems/data" in text   # matched category label
    assert "SSH brute force" in text                           # fired rule title (annexure)
    assert "chain intact" in text                              # integrity attestation
    assert seeded_vault["attacker_ip"] in text                 # unmasked IOC
    assert res["audit_ref"] in text                            # audit reference


def test_detailed_report_has_full_ir_sections(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    text = _text(res["pdf"])
    for heading in (
        "Detailed Incident Report", "Executive summary", "Statutory basis",
        "Incident timeline", "Technical analysis", "Impact",
        "Indicators of compromise", "Evidence provenance", "evidence log", "Response",
    ):
        assert heading in text, f"missing section: {heading}"
    assert "admin" in text
    assert "T1110.001" in text


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
