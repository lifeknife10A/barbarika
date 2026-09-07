"""Page 1 = the interactive CERT-In form, filled (editable by default; the audit's
single-line clipping is fixed by shrink-to-fit)."""

from __future__ import annotations

import re
from pathlib import Path

from pypdf import PdfReader

from barbarika_compliance import generate


def _generate(seeded_vault, submission_path, tmp_path, monkeypatch, *, flatten):
    monkeypatch.setenv("COMPLIANCE_AUDIT_LOG", str(tmp_path / "audit.log.jsonl"))
    out_pdf = str(tmp_path / f"report_{flatten}.pdf")
    generate.generate_report(
        db_path=seeded_vault["db"], submission_path=submission_path,
        out_pdf=out_pdf, incident="latest", key_path=seeded_vault["key"], flatten=flatten)
    return PdfReader(out_pdf)


def test_editable_keeps_form_fields(seeded_vault, submission_toml, tmp_path, monkeypatch):
    reader = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, flatten=False)
    assert reader.get_fields() and len(reader.get_fields()) >= 40


def test_flattened_has_no_form_fields(seeded_vault, submission_toml, tmp_path, monkeypatch):
    reader = _generate(seeded_vault, submission_toml, tmp_path, monkeypatch, flatten=True)
    assert not reader.get_fields()


def test_long_single_line_values_are_not_clipped(seeded_vault, submission_toml, tmp_path, monkeypatch):
    # The audit found single-line values silently clipped at the cell edge; shrink-
    # to-fit must keep the whole value. Assert on a flattened copy, where the painted
    # value text is extractable.
    long_app = ("nginx 1.24 reverse proxy + internal order API (Python/FastAPI) "
                "with Redis cache and Celery workers END-MARKER")
    text = Path(submission_toml).read_text()
    text = re.sub(r'application\s*=\s*".*"', f'application = "{long_app}"', text)
    sub = tmp_path / "sub_long.toml"
    sub.write_text(text, encoding="utf-8")
    reader = _generate(seeded_vault, str(sub), tmp_path, monkeypatch, flatten=True)
    page1 = reader.pages[0].extract_text() or ""
    assert "END-MARKER" in page1  # the tail survives -> not clipped
