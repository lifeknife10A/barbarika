"""Stamp filled values onto the AUTHENTIC CERT-In Incident Reporting Form.

The official form (compliance/template/CERT-In_Incident_Reporting_Form.pdf) is a
flat PDF with no fillable fields. Rather than redraw a lookalike, we overlay our
values at the form's own coordinates (measured from the shipped PDF) so the
output IS the government form, filled in. Checkboxes get an "X"; blanks get text.

Coordinates are in PDF points with a TOP-LEFT origin (as reported by the form's
text layout); we convert to ReportLab's bottom-left origin with H - y.
"""

from __future__ import annotations

import textwrap
from io import BytesIO
from pathlib import Path
from typing import Any

from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from . import certin
from .report import fmt_ist

_W, _H = A4  # 595.3 x 841.9 pt

FORM_PATH = (Path(__file__).resolve().parents[3] / "compliance" / "template"
             / "CERT-In_Incident_Reporting_Form.pdf")

# y (top-left origin) of each incident-type checkbox label, keyed by category id.
_TYPE_CHECKBOX_Y: dict[str, float] = {
    "iii": 287.1,   # Unauthorised access of IT systems/data
    "iv": 301.8,    # Defacement or intrusion into the website
    "v": 314.4,     # Malicious code attacks
    "x": 421.6,     # Attacks on Application such as E-Governance, E-Commerce etc.
}
_TYPE_CHECKBOX_X = 26.0  # left edge of the □ glyph column for the first type column


def _wrap(text: str, width: int) -> list[str]:
    out: list[str] = []
    for para in (text or "").splitlines() or [""]:
        out.extend(textwrap.wrap(para, width=width) or [""])
    return out


def overlay(ctx: dict[str, Any]) -> PdfReader:
    s = ctx["submission"]
    rep, af, asys = s["reporter"], s["affected_entity"], s["affected_system"]
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)

    def put(x: float, y_top: float, s_: str, size: float = 9, font: str = "Helvetica") -> None:
        if not s_:
            return
        c.setFont(font, size)
        c.drawString(x, _H - y_top, str(s_))

    def check(x: float, y_top: float) -> None:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(x, _H - y_top, "X")

    # --- "I am" ---
    if rep["i_am"].startswith("the effected"):
        check(66.0, 42.0)
    else:
        check(165.0, 41.5)

    # --- Contact Information of the Reporter ---
    put(120.0, 76.0, rep["name_role"], size=9)
    if rep["kind"] == "Individual":
        check(440.0, 75.5)
    else:
        check(497.0, 74.5)
    put(151.0, 94.5, rep["organization_name"], size=9)
    put(95.0, 112.5, rep["contact_no"], size=9)
    put(362.0, 112.5, rep["email"], size=9)
    for i, line in enumerate(_wrap(rep["address"], 95)[:3]):
        put(70.0, 141.0 + i * 12, line, size=9)

    # --- Basic Incident Details ---
    aff_entity = "Same as reporting entity" if af["same_as_reporter"] else af["name"]
    put(435.0, 205.0, aff_entity, size=9)

    # --- Incident Type checkbox (matched category) ---
    cid = ctx["cid"]
    if cid in _TYPE_CHECKBOX_Y:
        check(_TYPE_CHECKBOX_X, _TYPE_CHECKBOX_Y[cid] + 8.0)

    # --- Mission critical (Yes/No + note) ---
    put(435.0, 462.0, f'{asys["mission_critical"]} — ', size=9, font="Helvetica-Bold")
    for i, line in enumerate(_wrap(asys["mission_critical_note"], 42)[:3]):
        put(435.0, 462.0 + 12 + i * 11, line, size=8)

    # --- Basic Information of Affected System (right column, after each label) ---
    put(287.0, 506.5, asys["domain_url"], size=8)
    put(277.0, 521.8, ctx["affected_ip"], size=8)
    put(310.0, 537.3, asys["operating_system"], size=8)
    put(353.0, 552.8, asys["make_model_cloud"], size=8)
    put(387.0, 568.2, asys["application"], size=8)
    # Location label runs to the right margin; put its value on the blank line below.
    put(228.0, 596.0, asys["location"], size=8)
    put(344.0, 614.5, asys["isp"], size=8)

    # --- Brief description of Incident (left cell, below the label) ---
    desc = (f'{ctx["rule"].get("title", ctx["incident"].rule_title)}. '
            f'{ctx["attack_vector"]} '
            f'{len(ctx["incident"].events)} correlated events in the tamper-evident '
            f'vault (see attached Detailed Incident Report). '
            f'Impact: {s["incident"]["impact_summary"]}')
    for i, line in enumerate(_wrap(desc, 55)[:14]):
        put(30.0, 648.0 + i * 11, line, size=8)

    # --- Occurrence / Detection date & time (after the "hh:mm):" label) ---
    put(439.0, 632.0, fmt_ist(ctx["occurrence"]), size=8)
    put(431.0, 647.4, fmt_ist(ctx["detection"]), size=8)

    c.showPage()
    c.save()
    buf.seek(0)
    return PdfReader(buf)
