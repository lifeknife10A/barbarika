"""Stamp the checkbox "X" marks onto the LibreOffice-rendered CERT-In form PDF.

The text of the form is filled in the Word document (formdoc.py) so it lays out
inside the table cells; only the crosses are applied here, on the rendered PDF —
a small X inside a checkbox is position-tolerant, unlike flowing text. Each box
is located by searching the rendered PDF for its label, so this adapts to
whatever layout LibreOffice produced.
"""

from __future__ import annotations

from typing import Any

import pymupdf

from . import certin

# Distinctive text of each live category's incident-type label, so its box can
# be found (labels are verbatim in certin.INCIDENT_TYPES).
_CATEGORY_ANCHOR = {
    "i": "Targeted scanning", "ii": "Compromise of critical",
    "iii": "Unauthorised access of IT", "iv": "Defacement or intrusion",
    "v": "Malicious code attacks", "vi": "Attack on servers such as",
    "vii": "Identity Theft", "viii": "DoS/DDoS", "ix": "Attacks on Critical infrastructure",
    "x": "Attacks on Application such as E-Governance", "xi": "Data Breach",
    "xii": "Data Leak", "xvii": "Unauthorised access to social media",
}

_BOX = "☐"   # the empty ballot box we draw the X over


def _tick_before(page: pymupdf.Page, label: str) -> bool:
    """Find `label` on the page and draw an X in the checkbox just left of it.

    The template renders each item as "☐  <label>"; locate the ☐ glyph that
    immediately precedes the label and stamp the X there.
    """
    hits = page.search_for(label, quads=False)
    if not hits:
        return False
    rect = hits[0]
    # The box sits just left of the label; find the nearest ☐ on the same line.
    boxes = [b for b in page.search_for(_BOX) if abs(b.y0 - rect.y0) < 4 and b.x1 <= rect.x0 + 2]
    box = max(boxes, key=lambda b: b.x1) if boxes else None
    if box is not None:
        cx, cy = (box.x0 + box.x1) / 2, box.y1 - 1.5
    else:
        cx, cy = rect.x0 - 8, rect.y1 - 1.5
    page.insert_text((cx - 3.2, cy), "X", fontname="hebo", fontsize=9)
    return True


def apply(pdf_bytes: bytes, ctx: dict[str, Any]) -> bytes:
    """Return the form PDF with the reporter/entity/category checkboxes ticked."""
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    page = doc[0]
    s = ctx["submission"]
    rep = s["reporter"]

    if rep["i_am"].startswith("the effected"):
        _tick_before(page, "the effected entity")
    else:
        _tick_before(page, "reporting incident affecting")
    _tick_before(page, "Individual" if rep["kind"] == "Individual" else "Organization")

    anchor = _CATEGORY_ANCHOR.get(ctx["cid"] or "")
    if anchor:
        _tick_before(page, anchor)

    return doc.tobytes()
