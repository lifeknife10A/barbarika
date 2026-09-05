"""End-to-end fill: seeded vault -> official form PDF (flat) + audited email draft."""

from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader

from barbarika_compliance import generate


def _generate(seeded_vault, submission_toml, tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / "report.pdf")
    return generate.generate_report(
        db_path=seeded_vault["db"], submission_path=submission_toml,
        out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"],
    )


def test_pdf_is_produced_and_nontrivial(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    pdf = Path(res["pdf"])
    assert pdf.exists()
    assert pdf.stat().st_size > 3000
    reader = PdfReader(str(pdf))
    assert len(reader.pages) >= 2  # official form + evidence annexure


def test_pdf_is_flat_no_acroform(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    reader = PdfReader(res["pdf"])
    # A "stagnant" report has no interactive form fields.
    assert not reader.get_fields()
    root = reader.trailer["/Root"]
    assert "/AcroForm" not in root


def test_pdf_text_carries_the_statutory_essentials(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    reader = PdfReader(res["pdf"])
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert "Incident Reporting Form" in text            # authentic form title
    assert "Unauthorised access" in text                # category (iii) official wording
    assert "SSH brute force" in text                    # fired rule title
    assert "chain intact" in text                       # integrity attestation
    assert seeded_vault["attacker_ip"] in text          # unmasked IOC
    assert seeded_vault["reviewer"] in text             # human reviewer sign-off
    assert res["audit_ref"] in text                     # audit reference cited


def test_locked_pdf_metadata(seeded_vault, submission_toml, tmp_path, monkeypatch):
    res = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch)
    reader = PdfReader(res["pdf"])
    meta = reader.metadata
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
    assert res["audit_ref"] in log
    assert seeded_vault["incident_uuid"] in log
