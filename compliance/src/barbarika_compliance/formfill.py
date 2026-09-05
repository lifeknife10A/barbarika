"""Stamp filled values onto the AUTHENTIC CERT-In Incident Reporting Form.

The official form (compliance/template/CERT-In_Incident_Reporting_Form.pdf) is a
flat PDF with no fillable fields. Rather than redraw a lookalike, we write our
values directly onto it — located by the form's OWN text: for each field we find
the printed label, read its baseline, and place the value on that exact baseline
at the label's font size, so values sit on the form's lines instead of floating.
Checkboxes get an "X" in the box just left of their label. Everything is anchored
to the form's own layout, so there are no brittle hardcoded coordinates.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pymupdf

from . import certin
from .report import fmt_ist

FORM_PATH = (Path(__file__).resolve().parents[3] / "compliance" / "template"
             / "CERT-In_Incident_Reporting_Form.pdf")

_VALUE_SIZE = 10.5   # close to the form's 11pt Calibri labels, in Helvetica
_LINE = 12.5         # line advance for wrapped values

# Distinctive leading text of each live category's incident-type label, so the
# matched box can be located (the labels are verbatim in certin.INCIDENT_TYPES).
_SUBST = {"—": "-", "–": "-", "‘": "'", "’": "'",
          "“": '"', "”": '"', "…": "...", " ": " ", "·": "-"}


def _ascii(text: str) -> str:
    """Base-14 Helvetica only covers Latin-1; map common typography to ASCII."""
    for bad, good in _SUBST.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


_CATEGORY_ANCHOR = {
    "i": "Targeted scanning", "ii": "Compromise of critical",
    "iii": "Unauthorised access of IT", "iv": "Defacement or intrusion",
    "v": "Malicious code attacks", "vi": "Attack on servers such as",
    "vii": "Identity Theft", "viii": "DoS/DDoS", "ix": "Attacks on Critical infrastructure",
    "x": "Attacks on Application such as E-Governance", "xi": "Data Breach",
    "xii": "Data Leak", "xvii": "Unauthorised access to social media",
}


class _Form:
    """Small helper around the authentic form page for label-anchored writing."""

    def __init__(self) -> None:
        self.doc = pymupdf.open(str(FORM_PATH))
        self.page = self.doc[0]
        self._spans = [
            (s["text"], s["bbox"][0], s["bbox"][2], s["origin"][1], s["size"])
            for b in self.page.get_text("dict")["blocks"]
            for ln in b.get("lines", []) for s in ln["spans"]
        ]

    def label(self, needle: str, ymin: float = 0, ymax: float = 10_000):
        """Return (x0, x1, baseline_y) of the first span containing needle in
        the given y band, or None."""
        nl = needle.lower()
        for text, x0, x1, by, _size in self._spans:
            if nl in text.lower() and ymin <= by <= ymax:
                return x0, x1, by
        return None

    def write(self, x: float, baseline: float, text: str, size: float = _VALUE_SIZE) -> None:
        if text:
            self.page.insert_text((x, baseline), _ascii(text), fontname="helv", fontsize=size)

    def after(self, needle: str, value: str, *, gap: float = 6.0,
              ymin: float = 0, ymax: float = 10_000, size: float = _VALUE_SIZE) -> None:
        """Write a value just after a label, on the label's baseline."""
        loc = self.label(needle, ymin, ymax)
        if loc and value:
            _x0, x1, by = loc
            self.write(x1 + gap, by, value, size)

    def wrapped(self, needle: str, value: str, *, width: int, gap: float = 6.0,
                below: bool = False, x_wrap: float = 30.0, size: float = _VALUE_SIZE,
                max_lines: int | None = None) -> None:
        """Write a possibly multi-line value near a label. First line follows the
        label (or sits below it if below=True); continuation lines wrap left."""
        loc = self.label(needle)
        if not loc or not value:
            return
        x0, x1, by = loc
        lines: list[str] = []
        for para in value.splitlines() or [value]:
            lines.extend(textwrap.wrap(para, width=width) or [""])
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines]
            lines[-1] = lines[-1][:width - 24].rstrip() + " ... (see attached report)"
        if below:
            for i, ln in enumerate(lines):
                self.write(x_wrap, by + _LINE * (i + 1), ln, size)
        else:
            self.write(x1 + gap, by, lines[0], size)
            for i, ln in enumerate(lines[1:], start=1):
                self.write(x_wrap, by + _LINE * i, ln, size)

    def tick(self, needle: str, *, ymin: float = 0, ymax: float = 10_000) -> None:
        """Draw an X in the checkbox immediately left of a label."""
        loc = self.label(needle, ymin, ymax)
        if not loc:
            return
        x0, _x1, by = loc
        self.page.insert_text((x0 - 11.5, by), "X", fontname="hebo", fontsize=10)

    def to_bytes(self) -> bytes:
        return self.doc.tobytes()


def fill_form_page(ctx: dict[str, Any]) -> bytes:
    """Fill the authentic form and return the single-page PDF as bytes."""
    s = ctx["submission"]
    rep, af, asys = s["reporter"], s["affected_entity"], s["affected_system"]
    f = _Form()

    # I am / Individual / Organization (reporter region only)
    if rep["i_am"].startswith("the effected"):
        f.tick("the effected entity", ymax=60)
    else:
        f.tick("reporting incident affecting", ymax=60)
    if rep["kind"] == "Individual":
        f.tick("Individual", ymin=60, ymax=90)
    else:
        f.tick("Organization", ymin=60, ymax=90)

    # Contact Information of the Reporter
    f.after("Name & Role/Title", rep["name_role"])
    f.after("Organization name (if any)", rep["organization_name"])
    f.after("Contact No.", rep["contact_no"])
    f.after("Email:", rep["email"])
    f.wrapped("Address:", rep["address"], width=42)

    # Basic Incident Details
    aff_entity = "Same as reporting entity" if af["same_as_reporter"] else af["name"]
    loc = f.label("Affected entity")
    if loc:
        f.write(430.0, loc[2], aff_entity)

    # Incident Type — tick the matched category's box
    anchor = _CATEGORY_ANCHOR.get(ctx["cid"] or "")
    if anchor:
        f.tick(anchor, ymin=250, ymax=440)

    # Mission critical (Yes/No + note) in the right cell
    mc = f.label("Is the affected system")
    if mc:
        f.write(430.0, mc[2], f'{asys["mission_critical"]} -')
        for i, ln in enumerate(textwrap.wrap(asys["mission_critical_note"], 40)[:3]):
            f.write(430.0, mc[2] + _LINE * (i + 1), ln, size=9)

    # Basic Information of Affected System (inline labels)
    f.after("Domain/URL", asys["domain_url"])
    f.after("IP Address", ctx["affected_ip"])
    f.after("Operating System", asys["operating_system"])
    f.after("Make/ Model", asys["make_model_cloud"])
    f.after("Affected Application details", asys["application"])
    f.wrapped("Location of affected", asys["location"], width=48, below=True, x_wrap=226.0)
    f.after("Network and name of ISP", asys["isp"])

    # Brief description of Incident (left cell, below the label). Kept concise —
    # the full technical analysis, IOCs and integrity attestation are in the
    # attached Detailed Incident Report — and capped so it can't run into the Note.
    desc = (f'{ctx["rule"].get("title", ctx["incident"].rule_title)}. '
            f'{len(ctx["incident"].events)} correlated events in the tamper-evident '
            f'vault (full analysis in the attached Detailed Incident Report). '
            f'Impact: {s["incident"]["impact_summary"]}')
    f.wrapped("Brief description of Incident", desc, width=45, below=True,
              x_wrap=30.0, size=9, max_lines=9)

    # Occurrence / Detection date & time. The label is split into several spans
    # ("... (dd/mm/yyyy" | "hh:mm" | "):"), so anchor on the "hh:mm" span at the
    # end of each line (occurrence ~y631, detection ~y646) to land after "):".
    f.after("hh:mm", fmt_ist(ctx["occurrence"]), gap=14, ymin=625, ymax=638)
    f.after("hh:mm", fmt_ist(ctx["detection"]), gap=14, ymin=640, ymax=655)

    return f.to_bytes()
