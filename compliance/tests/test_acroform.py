"""Page 1 = the interactive CERT-In form, filled and flattened (pypdf-only)."""

from __future__ import annotations

import re
from pathlib import Path

from pypdf import PdfReader

from barbarika_compliance import generate


def _pdf(seeded_vault, submission_toml, tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / "report.pdf")
    generate.generate_report(
        db_path=seeded_vault["db"], submission_path=submission_toml,
        out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"])
    return PdfReader(out_pdf)


def test_form_page_is_flattened(seeded_vault, submission_toml, tmp_path, monkeypatch):
    reader = _pdf(seeded_vault, submission_toml, tmp_path, monkeypatch)
    # Page 1 is the government form; it must carry no interactive widgets.
    assert "/Annots" not in reader.pages[0] or not [
        a.get_object() for a in reader.pages[0].get("/Annots", [])
        if a.get_object().get("/Subtype") == "/Widget"
    ]
    assert not reader.get_fields()


def test_long_single_line_values_are_not_clipped(seeded_vault, submission_toml, tmp_path, monkeypatch):
    # The audit found single-line values silently clipped at the cell edge;
    # shrink-to-fit must keep the whole value (its tail) on the page.
    long_app = ("nginx 1.24 reverse proxy + internal order API (Python/FastAPI) "
                "with Redis cache and Celery workers END-MARKER")
    text = Path(submission_toml).read_text()
    text = re.sub(r'application\s*=\s*".*"', f'application = "{long_app}"', text)
    sub = tmp_path / "sub_long.toml"
    sub.write_text(text, encoding="utf-8")

    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / "report_long.pdf")
    generate.generate_report(
        db_path=seeded_vault["db"], submission_path=str(sub),
        out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"])
    page1 = PdfReader(out_pdf).pages[0].extract_text() or ""
    # The tail of the long value survives -> not clipped.
    assert "END-MARKER" in page1


def test_matched_category_label_present(seeded_vault, submission_toml, tmp_path, monkeypatch):
    reader = _pdf(seeded_vault, submission_toml, tmp_path, monkeypatch)
    page1 = reader.pages[0].extract_text() or ""
    assert "Unauthorised access of IT systems/data" in page1
