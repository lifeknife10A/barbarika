"""Fill the authentic CERT-In Incident Reporting Form as an editable Word (DOCX).

The submittable PDF is produced from the interactive AcroForm template
(see acroform.py). This module fills the same form's real Word table cells to
provide an *editable* companion deliverable (the dashboard's "Editable .docx"
button) — text wraps inside each cell, so nothing crosses a divider. No
LibreOffice needed: python-docx only.

The template DOCX is a single 15-row table; the cell map below was measured from
compliance/template/CERT-In_Incident_Reporting_Form.docx.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import docx
from docx.text.paragraph import Paragraph

from .report import fmt_ist

TEMPLATE_DOCX = (Path(__file__).resolve().parents[3] / "compliance" / "template"
                 / "CERT-In_Incident_Reporting_Form.docx")


def _uniq_cells(row) -> list:
    """The distinct cells of a (merged) row, left to right."""
    out, seen = [], set()
    for c in row.cells:
        if id(c._tc) not in seen:
            seen.add(id(c._tc))
            out.append(c)
    return out


def _style_from(src_run, dst_run) -> None:
    """Copy font name/size from an existing (label) run so the value matches."""
    if src_run is None:
        return
    dst_run.font.name = src_run.font.name
    if src_run.font.size is not None:
        dst_run.font.size = src_run.font.size
    dst_run.font.bold = False


def _append_value(paragraph: Paragraph, value: str) -> None:
    """Append a value run after a label's text within the same paragraph."""
    if not value:
        return
    src = paragraph.runs[-1] if paragraph.runs else None
    run = paragraph.add_run(("  " if not paragraph.text.endswith(" ") else " ") + str(value))
    _style_from(src, run)


def _set_cell_value(cell, value: str, *, para_index: int = 0) -> None:
    """Write a value into an (otherwise empty) value cell, keeping its font."""
    para = cell.paragraphs[para_index]
    if para.runs:
        # Overwrite the placeholder run's text (keeps the cell's font/size).
        para.runs[0].text = str(value or "")
        for extra in para.runs[1:]:
            extra.text = ""
    else:
        _append_value(para, value)


def _find_label_para(cell, label_prefix: str) -> Paragraph | None:
    for p in cell.paragraphs:
        if p.text.strip().lower().startswith(label_prefix.strip().lower()):
            return p
    return None


def fill_form(ctx: dict[str, Any], out_docx: str) -> str:
    """Fill the template DOCX from the report context and save to out_docx."""
    s = ctx["submission"]
    rep, af, asys = s["reporter"], s["affected_entity"], s["affected_system"]
    d = docx.Document(str(TEMPLATE_DOCX))
    t = d.tables[0]
    rows = [_uniq_cells(r) for r in t.rows]

    # R2: Name & Role/Title (value appended after the label in c0)
    _append_value(rows[2][0].paragraphs[0], rep["name_role"])
    # R3: Organization name (empty value cell)
    _set_cell_value(rows[3][1], rep["organization_name"])
    # R4: Contact No. (c1) and Email (c3)
    _set_cell_value(rows[4][1], rep["contact_no"])
    _set_cell_value(rows[4][3], rep["email"])
    # R5: Address (empty cell, may wrap across its paragraphs)
    _set_cell_value(rows[5][1], rep["address"])
    # R7: Affected entity
    aff_entity = "Same as reporting entity" if af["same_as_reporter"] else af["name"]
    _set_cell_value(rows[7][1], aff_entity)
    # R10: mission critical (Yes/No + note)
    note = asys["mission_critical_note"]
    mc = f'{asys["mission_critical"]} — {note}' if note else asys["mission_critical"]
    _set_cell_value(rows[10][1], mc)

    # R11 c1: affected-system inline labels — append each value after its label
    sysc = rows[11][1]
    field_map = [
        ("Domain/URL", asys["domain_url"]),
        ("IP Address", ctx["affected_ip"]),
        ("Operating System", asys["operating_system"]),
        ("Make/", asys["make_model_cloud"]),
        ("Affected Application", asys["application"]),
        ("Location of affected", asys["location"]),
        ("Network and name of ISP", asys["isp"]),
    ]
    for prefix, value in field_map:
        para = _find_label_para(sysc, prefix)
        if para is not None:
            _append_value(para, value)

    # R12 c0: Brief description of Incident (append below the label)
    desc = (f'{ctx["rule"].get("title", ctx["incident"].rule_title)}. '
            f'{ctx["attack_vector"]} '
            f'{len(ctx["incident"].events)} correlated events recorded in the '
            f'tamper-evident vault (see attached Detailed Incident Report). '
            f'Impact: {s["incident"]["impact_summary"]}')
    _append_value(rows[12][0].paragraphs[0], desc)

    # R12 c1: Occurrence / Detection date & time (append after each inline label)
    datec = rows[12][1]
    occ = _find_label_para(datec, "Occurrence date")
    det = _find_label_para(datec, "Detection date")
    if occ is not None:
        _append_value(occ, fmt_ist(ctx["occurrence"]))
    if det is not None:
        _append_value(det, fmt_ist(ctx["detection"]))

    d.save(out_docx)
    return out_docx
