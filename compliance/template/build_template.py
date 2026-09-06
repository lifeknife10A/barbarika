"""Repair the uploaded CERT-In form DOCX into a clean, render-faithful template.

The raw DOCX conversion the user supplied is faithful for the Contact/Basic-detail
rows (real table cells -> text wraps correctly), but two things render badly under
LibreOffice:
  1. the checkbox glyph is Wingdings U+F06F, which has no font here and renders as
     tofu -> swap every checkbox to U+2610 BALLOT BOX in DejaVu Sans;
  2. the "Incident Type" block was flattened into ONE cell with the three columns'
     text interleaved into unreadable run-on lines -> rebuild it as a clean,
     borderless 3-column nested table (fixed layout, so LibreOffice keeps the
     columns wide) from the 20 verbatim official labels.

Run once to regenerate compliance/template/CERT-In_Incident_Reporting_Form.docx
from the pristine upload. Idempotent; keep for provenance.
"""

from __future__ import annotations

import sys
from pathlib import Path

import docx
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt

HERE = Path(__file__).resolve().parent
SRC = sys.argv[1] if len(sys.argv) > 1 else str(HERE / "CERT-In_Incident_Reporting_Form.docx")
OUT = str(HERE / "CERT-In_Incident_Reporting_Form.docx")

BOX = "\u2610"   # BALLOT BOX (renders in DejaVu Sans)
BOX_FONT = "DejaVu Sans"
WINGDING_BOX = "\uf06f"  # Wingdings box glyph in the source (tofu without Wingdings)

from barbarika_compliance.certin import INCIDENT_TYPES  # noqa: E402

LABELS = [label for _cid, label in INCIDENT_TYPES]
# Authentic 3-column split: left 10 (i–x), middle 8 (xi–xviii), right 2 (xix–xx) + Other.
COL0 = LABELS[0:10]
COL1 = LABELS[10:18]
COL2 = LABELS[18:20] + ["Other (Please Specify)"]


def _set_font(run, name: str) -> None:
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = rpr.makeelement(qn("w:rFonts"), {})
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs"):
        rfonts.set(qn(attr), name)


def _iter_table_paragraphs(t):
    for row in t.rows:
        for cell in row.cells:
            yield from cell.paragraphs
            for nt in cell.tables:
                yield from _iter_table_paragraphs(nt)


def _iter_paragraphs(doc):
    yield from doc.paragraphs
    for t in doc.tables:
        yield from _iter_table_paragraphs(t)


def _fix_checkbox_runs(doc) -> int:
    """Replace every Wingdings box glyph with a rendering ballot box."""
    n = 0
    for para in _iter_paragraphs(doc):
        for run in para.runs:
            if WINGDING_BOX in run.text:
                run.text = run.text.replace(WINGDING_BOX, BOX)
                _set_font(run, BOX_FONT)
                n += 1
    return n


def _uniq_cells(row):
    out, seen = [], set()
    for c in row.cells:
        if id(c._tc) not in seen:
            seen.add(id(c._tc))
            out.append(c)
    return out


def _rebuild_incident_type(cell) -> None:
    """Replace the flattened Incident Type cell with a clean single-column
    checklist. The full-width R9 cell wraps text correctly on its own (like the
    Note row), so this is robust — nested/multi-column tables collapse under
    LibreOffice inside this form's outer grid. At full width most labels sit on
    one line, so the height is comparable to the official 3-column layout."""
    for p in list(cell.paragraphs):
        p._element.getparent().remove(p._element)
    labels = COL0 + COL1 + COL2   # all 20 types + "Other (Please Specify)"
    for lab in labels:
        p = cell.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(1)
        box = p.add_run(BOX + "  ")
        box.font.size = Pt(8)
        box.font.bold = False
        _set_font(box, BOX_FONT)
        txt = p.add_run(lab)
        txt.font.size = Pt(8)
        txt.font.bold = False


def main() -> int:
    doc = docx.Document(SRC)
    fixed = _fix_checkbox_runs(doc)
    table = doc.tables[0]
    _rebuild_incident_type(_uniq_cells(table.rows[9])[0])   # Row 9 = Incident Type
    doc.save(OUT)
    print(f"repaired: {fixed} checkbox glyphs fixed; Incident Type rebuilt -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
