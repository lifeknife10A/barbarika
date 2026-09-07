"""Fill the AUTHENTIC interactive CERT-In form (an AcroForm PDF with 44 named
fields) and flatten it to a static page — the page-1 engine for the report.

Adapted from the interactive-template approach on the `krishna` branch (which is
cleaner than drawing on a flat PDF or round-tripping DOCX through LibreOffice):
values go into real form fields, so text stays inside the cells and the output is
pixel-identical to the government form. We:
  * verify the template's recorded SHA-256 before every run (immutable master),
  * map our re-verified incident context onto the field names,
  * write our own appearance streams (pypdf mis-encodes apostrophes) with a
    shrink-to-fit so long single-line values are not silently clipped
    (the one defect found when auditing the krishna output),
  * flatten to a static, non-editable page.
"""

from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from typing import Any

import pymupdf
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    StreamObject,
    TextStringObject,
)

from .report import fmt_ist

_TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "compliance" / "template"
TEMPLATE_PATH = _TEMPLATE_DIR / "cert_in_annexure_i_interactive.pdf"
RECORDED_HASH_PATH = _TEMPLATE_DIR / "cert_in_annexure_i_interactive.sha256"

_FIXED_DA = "/Helv 9 Tf 0 g"
_FONT_SIZE = 9.0
_MIN_FONT_SIZE = 6.0
_PAD = 2.0
_MULTILINE_FLAG = 1 << 12
_WRAP_WIDTH = 88


class TemplateIntegrityError(RuntimeError):
    """The tracked interactive template no longer matches its recorded hash."""


# --- field names (from the krishna field_registry; the template's own names) ---

# Our CERT-In category numeral -> the template's category checkbox field name.
CATEGORY_FIELD: dict[str, str] = {
    "i": "incident_category_targeted_scanning",
    "ii": "incident_category_critical_system_compromise",
    "iii": "incident_category_unauthorized_access",
    "iv": "incident_category_defacement_or_intrusion",
    "v": "incident_category_malicious_code",
    "vi": "incident_category_server_or_network_device_attack",
    "vii": "incident_category_identity_theft_or_phishing",
    "viii": "incident_category_dos_or_ddos",
    "ix": "incident_category_critical_infrastructure_or_scada",
    "x": "incident_category_application_attack",
    "xi": "incident_category_data_breach",
    "xii": "incident_category_data_leak",
    "xiii": "incident_category_iot_attack",
    "xiv": "incident_category_digital_payment_attack",
    "xv": "incident_category_malicious_mobile_app",
    "xvi": "incident_category_fake_mobile_app",
    "xvii": "incident_category_social_media_unauthorized_access",
    "xviii": "incident_category_cloud_attack",
    "xix": "incident_category_emerging_technology_attack",
    "xx": "incident_category_ai_or_ml_attack",
}


def _verify_template() -> str:
    actual = hashlib.sha256(TEMPLATE_PATH.read_bytes()).hexdigest()
    recorded = RECORDED_HASH_PATH.read_text().strip()
    if actual != recorded:
        raise TemplateIntegrityError(
            f"interactive template {TEMPLATE_PATH} hash {actual} != recorded "
            f"{recorded}; refusing to generate from a modified master"
        )
    return actual


# --- context -> field values --------------------------------------------------

def build_field_values(ctx: dict[str, Any]) -> dict[str, str | bool]:
    """Map our re-verified incident context onto the 44 template field names.

    Text fields get str, checkbox fields get bool. Every category checkbox is
    written explicitly (matched -> True, all others -> False)."""
    s = ctx["submission"]
    rep, af, asys = s["reporter"], s["affected_entity"], s["affected_system"]
    v: dict[str, str | bool] = {}

    def put(name: str, value: object) -> None:
        if value is None:
            return
        text = str(value).strip()
        if text:
            v[name] = text

    effected = rep["i_am"].startswith("the effected")
    v["reporter_is_affected_entity"] = effected
    v["reporter_is_reporting_for_other_entity"] = not effected
    is_org = rep["kind"] != "Individual"
    v["reporter_is_individual"] = not is_org
    v["reporter_is_organization"] = is_org

    put("reporter_name_and_role", rep["name_role"])
    put("reporter_organization_name", rep["organization_name"])
    put("reporter_contact_number", rep["contact_no"])
    put("reporter_email", rep["email"])
    put("reporter_address", rep["address"])

    aff_name = rep["organization_name"] if af["same_as_reporter"] else af["name"]
    put("affected_entity_name", aff_name or "Same as reporting entity")

    note = asys.get("mission_critical_note") or ""
    mc = f'{asys["mission_critical"]} - {note}'.strip(" -") if note else asys["mission_critical"]
    put("mission_criticality_and_details", mc)

    put("affected_system_domain_url", asys["domain_url"])
    put("affected_system_ip_address", ctx["affected_ip"])
    put("affected_system_operating_system", asys["operating_system"])
    put("affected_system_cloud_or_model_details", asys["make_model_cloud"])
    put("affected_system_application_details", asys["application"])
    put("affected_system_location", asys["location"])
    put("affected_system_network_and_isp", asys["isp"])

    put("incident_occurrence_at", fmt_ist(ctx["occurrence"]))
    put("incident_detection_at", fmt_ist(ctx["detection"]))

    desc = (f'{ctx["rule"].get("title", ctx["incident"].rule_title)}. '
            f'{ctx["attack_vector"]} '
            f'{len(ctx["incident"].events)} correlated events in the tamper-evident '
            f'vault (full analysis in the attached Detailed Incident Report). '
            f'Impact: {s["incident"]["impact_summary"]}')
    put("incident_description", desc)

    matched = CATEGORY_FIELD.get(ctx["cid"] or "")
    for field_name in CATEGORY_FIELD.values():
        v[field_name] = field_name == matched
    v["incident_category_other"] = matched is None
    return v


# --- appearance streams (own, correctly encoded, shrink-to-fit) ---------------

def _pdf_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _helv_width(text: str, size: float) -> float:
    return pymupdf.get_text_length(text, fontname="helv", fontsize=size)


def _fit_size(text: str, width: float) -> float:
    """Largest font size (<= 9pt, >= 6pt) at which `text` fits one line width."""
    usable = max(width - 2 * _PAD, 1.0)
    size = _FONT_SIZE
    while size > _MIN_FONT_SIZE and _helv_width(text, size) > usable:
        size -= 0.25
    return size


def _text_appearance(width: float, height: float, lines: list[str], *, multiline: bool) -> bytes:
    if multiline:
        size = _FONT_SIZE
        start_y = height - _PAD - size
    else:
        size = _fit_size(lines[0] if lines else "", width)  # shrink-to-fit, no clip
        start_y = max(_PAD, (height - size) / 2 + size * 0.22)
    leading = size * 1.16
    ops = [
        "/Tx BMC", "q",
        f"{_PAD:.2f} {_PAD:.2f} {max(width - 2 * _PAD, 1):.2f} "
        f"{max(height - 2 * _PAD, 1):.2f} re W n",
        "BT", f"/Helv {size:.2f} Tf 0 g", f"{leading:.2f} TL",
        f"1 0 0 1 {_PAD:.2f} {start_y:.2f} Tm",
    ]
    for i, line in enumerate(lines or [""]):
        if i:
            ops.append("T*")
        ops.append(f"({_pdf_escape(line)}) Tj")
    ops += ["ET", "Q", "EMC"]
    return "\n".join(ops).encode("latin-1", "replace")


def _checkmark_stream(width: float, height: float) -> bytes:
    pad = 1.0
    bw, bh = max(width - 2 * pad, 1.0), max(height - 2 * pad, 1.0)
    x1, y1 = pad + 0.05 * bw, pad + 0.52 * bh
    x2, y2 = pad + 0.38 * bw, pad + 0.08 * bh
    x3, y3 = pad + 0.98 * bw, pad + 0.94 * bh
    lw = max(0.6, 0.11 * min(bw, bh))
    return (f"q {lw:.2f} w 0 0 0 RG 1 J 1 j "
            f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l {x3:.2f} {y3:.2f} l S Q").encode("latin-1")


def _restyle_widgets(writer: PdfWriter) -> None:
    acro = writer._root_object["/AcroForm"]
    acro[NameObject("/DA")] = TextStringObject(_FIXED_DA)
    for annot in writer.pages[0].get("/Annots", []):
        obj = annot.get_object()
        ft = obj.get("/FT")
        if ft == "/Tx":
            obj[NameObject("/DA")] = TextStringObject(_FIXED_DA)
            mk = obj.get("/MK")
            if not isinstance(mk, DictionaryObject):
                mk = DictionaryObject()
                obj[NameObject("/MK")] = mk
            mk[NameObject("/BG")] = ArrayObject([FloatObject(1), FloatObject(1), FloatObject(1)])
        elif ft == "/Btn":
            mk = obj.get("/MK")
            if isinstance(mk, DictionaryObject):
                mk[NameObject("/CA")] = TextStringObject("4")
            rect = [float(x) for x in obj["/Rect"]]
            w, h = rect[2] - rect[0], rect[3] - rect[1]
            on_state = obj.get("/AP", {}).get("/N", {}).get("/On")
            if on_state is not None:
                on_state.get_object().set_data(_checkmark_stream(w, h))


def _multiline_fields(writer: PdfWriter) -> set[str]:
    names: set[str] = set()
    for annot in writer.pages[0].get("/Annots", []):
        obj = annot.get_object()
        if obj.get("/FT") == "/Tx" and int(obj.get("/Ff", 0) or 0) & _MULTILINE_FLAG:
            names.add(str(obj.get("/T")))
    return names


def _render_text_appearances(writer: PdfWriter, resolved: dict[str, str], multiline: set[str]) -> None:
    acro = writer._root_object["/AcroForm"]
    helv_ref = acro["/DR"]["/Font"].raw_get("/Helv")
    resources = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/Helv"): helv_ref})})
    for annot in writer.pages[0].get("/Annots", []):
        obj = annot.get_object()
        name = str(obj.get("/T"))
        if obj.get("/FT") != "/Tx" or name not in resolved:
            continue
        is_multiline = name in multiline
        lines = resolved[name].split("\n") if is_multiline else [resolved[name]]
        rect = [float(x) for x in obj["/Rect"]]
        w, h = rect[2] - rect[0], rect[3] - rect[1]
        stream = StreamObject()
        stream.set_data(_text_appearance(w, h, lines, multiline=is_multiline))
        stream[NameObject("/Type")] = NameObject("/XObject")
        stream[NameObject("/Subtype")] = NameObject("/Form")
        stream[NameObject("/FormType")] = NumberObject(1)
        stream[NameObject("/BBox")] = ArrayObject(
            [FloatObject(0), FloatObject(0), FloatObject(w), FloatObject(h)])
        stream[NameObject("/Resources")] = resources
        obj[NameObject("/AP")] = DictionaryObject({NameObject("/N"): writer._add_object(stream)})


def _soft_wrap(text: str) -> str:
    import textwrap
    lines: list[str] = []
    for para in text.splitlines() or [text]:
        lines.extend(textwrap.wrap(para, width=_WRAP_WIDTH) or [""])
    return "\n".join(lines)


def _flatten_page(writer: PdfWriter) -> None:
    page = writer.pages[0]
    resources = page.get("/Resources")
    if not isinstance(resources, DictionaryObject):
        resources = DictionaryObject()
        page[NameObject("/Resources")] = resources
    xobjects = resources.get("/XObject")
    if not isinstance(xobjects, DictionaryObject):
        xobjects = DictionaryObject()
        resources[NameObject("/XObject")] = xobjects
    draw_ops: list[str] = []
    for index, annot in enumerate(page.get("/Annots", [])):
        obj = annot.get_object()
        if obj.get("/Subtype") != "/Widget":
            continue
        normal = obj.get("/AP", {}).get("/N")
        if normal is None:
            continue
        appearance = normal.get_object()
        if obj.get("/FT") == "/Btn":
            state = obj.get("/AS")
            if not isinstance(appearance, StreamObject):
                if state is None or state not in appearance:
                    continue
                appearance = appearance[state].get_object()
            elif state != NameObject("/On"):
                continue
        rect = [float(x) for x in obj["/Rect"]]
        alias = NameObject(f"/BbkFld{index}")
        xobjects[alias] = writer._add_object(appearance)
        draw_ops.append(f"q 1 0 0 1 {rect[0]:.2f} {rect[1]:.2f} cm {alias} Do Q")
    if draw_ops:
        overlay = StreamObject()
        overlay.set_data(("\n" + "\n".join(draw_ops) + "\n").encode("latin-1"))
        base = page.get_contents()
        page[NameObject("/Contents")] = ArrayObject(
            [writer._add_object(base), writer._add_object(overlay)])
    if "/Annots" in page:
        del page[NameObject("/Annots")]
    if "/AcroForm" in writer._root_object:
        del writer._root_object[NameObject("/AcroForm")]


def fill_form_pdf(ctx: dict[str, Any]) -> bytes:
    """Return the official form as a flat (non-editable) one-page PDF, filled."""
    _verify_template()
    values = build_field_values(ctx)
    reader = PdfReader(str(TEMPLATE_PATH))
    writer = PdfWriter()
    writer.append(reader)  # keeps AcroForm tree, widgets, page content
    multiline = _multiline_fields(writer)
    resolved: dict[str, str] = {}
    for name, value in values.items():
        if isinstance(value, bool):
            resolved[name] = "/On" if value else "/Off"
        elif name in multiline:
            resolved[name] = _soft_wrap(value)
        else:
            resolved[name] = value
    _restyle_widgets(writer)
    writer.update_page_form_field_values(writer.pages[0], resolved, auto_regenerate=False)
    _render_text_appearances(writer, resolved, multiline)
    _flatten_page(writer)
    buf = BytesIO()
    writer.write(buf)
    return buf.getvalue()
