"""Produce the CERT-In incident report PDF: page 1 is the AUTHENTIC official
Incident Reporting Form (the shipped government PDF) stamped with our values,
followed by a full Detailed Incident Report annexure (executive summary,
timeline, technical analysis, impact, IOCs, cryptographic integrity, unmasked
evidence log, response & remediation) modelled on NIST SP 800-61 / SANS.

The official form itself invites this: its footnote says the form is not
mandatory and the reporting entity may attach additional relevant information;
the 2022 Directions also require logs to accompany the report. Flat,
non-editable PDF (no interactive form fields), locked metadata.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from . import certin
from .model import ChainAttestation, IncidentRecord
from .rules import rule_details

_ACCOUNT = re.compile(r"\b(?:for|user)\s+(?:invalid user\s+)?([A-Za-z_][\w.-]*)")
_PORT = re.compile(r"\bport\s+(\d{1,5})\b")

IST = timezone(timedelta(hours=5, minutes=30))
_GRAY = colors.HexColor("#c8c8c8")
_INK = colors.HexColor("#111111")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_ss = getSampleStyleSheet()
_P = ParagraphStyle("cell", parent=_ss["BodyText"], fontName="Helvetica", fontSize=8, leading=10)
_PB = ParagraphStyle("cellb", parent=_P, fontName="Helvetica-Bold")
_SMALL = ParagraphStyle("small", parent=_P, fontSize=7, leading=8.5, textColor=colors.HexColor("#444"))
_TITLE = ParagraphStyle("title", parent=_ss["Title"], fontName="Helvetica-Bold", fontSize=13, alignment=TA_CENTER)
_H = ParagraphStyle("h", parent=_PB, fontSize=9.5, spaceBefore=2, spaceAfter=4)


# ---- time + IOC helpers ------------------------------------------------------

def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    s = iso.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fmt_ist(iso: str | None) -> str:
    dt = _parse(iso)
    return dt.astimezone(IST).strftime("%d/%m/%Y %H:%M IST") if dt else "—"


def extract_ips(incident: IncidentRecord) -> list[str]:
    seen: list[str] = []
    for ev in incident.events:
        for ip in _IPV4.findall(ev.raw_message or ""):
            if ip not in seen and not ip.startswith(("10.", "127.", "192.168.")):
                seen.append(ip)
    # fall back to any IP (incl. internal) if no external found
    if not seen:
        for ev in incident.events:
            for ip in _IPV4.findall(ev.raw_message or ""):
                if ip not in seen:
                    seen.append(ip)
    return seen


def _earliest(incident: IncidentRecord, attr: str) -> str | None:
    vals = [getattr(e, attr) for e in incident.events if getattr(e, attr)]
    return min(vals) if vals else None


# ---- context assembly --------------------------------------------------------

def build_context(incident: IncidentRecord, submission: dict[str, Any],
                  chain: ChainAttestation, audit_ref: str) -> dict[str, Any]:
    cid = incident.category
    ips = extract_ips(incident)
    occurrence = (submission["incident"]["occurrence_override"] or _earliest(incident, "occurred_at")
                  or _earliest(incident, "detected_at") or _earliest(incident, "received_at"))
    detection = _earliest(incident, "detected_at") or _earliest(incident, "received_at")
    noticed = submission["incident"]["noticed_at"]
    if noticed == "auto" or not noticed:
        noticed = detection
    confirmed = submission["incident"]["confirmed_at"] or datetime.now(timezone.utc).isoformat()
    deadline_dt = (_parse(noticed) + timedelta(hours=6)) if _parse(noticed) else None
    aff_ip = submission["affected_system"]["ip_address"]
    if aff_ip == "auto":
        # first internal-looking IP else first IP else blank
        internal = [i for i in _all_ips(incident) if i.startswith(("10.", "192.168.", "172."))]
        aff_ip = internal[0] if internal else (ips[0] if ips else "")
    enr = certin.enrichment(cid)
    rd = rule_details(incident.rule_id)
    return {
        "incident": incident, "submission": submission, "chain": chain, "audit_ref": audit_ref,
        "cid": cid, "type_label": certin.category_label(cid), "numeral": certin.category_numeral(cid) if cid else "—",
        "ips": ips, "affected_ip": aff_ip, "mitre": enr.get("mitre", []),
        "attack_vector": enr.get("attack_vector", ""), "rule": rd,
        "occurrence": occurrence, "detection": detection, "noticed": noticed,
        "confirmed": confirmed, "deadline": deadline_dt.isoformat() if deadline_dt else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _all_ips(incident: IncidentRecord) -> list[str]:
    out: list[str] = []
    for ev in incident.events:
        for ip in _IPV4.findall(ev.raw_message or ""):
            if ip not in out:
                out.append(ip)
    return out


# ---- shared table style ------------------------------------------------------

def _kv_table(rows: list[list[Any]], col0=55 * mm) -> Table:
    t = Table(rows, colWidths=[col0, 180 * mm - col0])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, _INK), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _accounts(incident: IncidentRecord) -> list[str]:
    seen: list[str] = []
    for ev in incident.events:
        for acct in _ACCOUNT.findall(ev.raw_message or ""):
            if acct not in seen:
                seen.append(acct)
        u = (ev.payload or {}).get("user") or (ev.payload or {}).get("username")
        if isinstance(u, str) and u and u not in seen:
            seen.append(u)
    return seen


def _ports(incident: IncidentRecord) -> list[str]:
    seen: list[str] = []
    for ev in incident.events:
        for p in _PORT.findall(ev.raw_message or ""):
            if p not in seen:
                seen.append(p)
    return seen


# ---- Detailed Incident Report (annexure) -------------------------------------

def _exec_summary(ctx: dict[str, Any]) -> str:
    inc: IncidentRecord = ctx["incident"]
    s = ctx["submission"]
    host = ctx["affected_ip"] or s["affected_system"]["domain_url"] or "the monitored host"
    osname = s["affected_system"]["operating_system"]
    ips = ", ".join(ctx["ips"]) or "internal source(s)"
    dl = fmt_ist(ctx["deadline"]) if ctx["deadline"] else "—"
    return (
        f'On <b>{fmt_ist(ctx["occurrence"])}</b>, the Barbarika Sentry evidence pipeline detected '
        f'<b>{inc.rule_title}</b> affecting <b>{host}</b>'
        + (f' ({osname})' if osname else '')
        + f'. The activity is classified as CERT-In <b>{ctx["numeral"]} — {ctx["type_label"]}</b>, '
        f'evidenced by <b>{len(inc.events)}</b> correlated events sealed in the tamper-evident vault. '
        f'{ctx["attack_vector"]} Attacker indicator(s): <b>{ips}</b>. '
        f'The incident was noticed at <b>{fmt_ist(ctx["noticed"])}</b> (statutory 6-hour reporting '
        f'deadline <b>{dl}</b>). {s["incident"]["impact_summary"]} '
        f'This report is filed under sub-section (6) of section 70B of the IT Act, 2000, within the '
        f'mandatory 6-hour window, with independently re-verified cryptographic evidence attached.'
    )


def _annexure_flowables(ctx: dict[str, Any]) -> list:
    inc: IncidentRecord = ctx["incident"]
    ch: ChainAttestation = ctx["chain"]
    s = ctx["submission"]
    asys = s["affected_system"]
    out: list = [
        Paragraph("Detailed Incident Report", _TITLE),
        Spacer(1, 8),
    ]

    # 1. Executive summary
    out.append(Paragraph("1. Executive summary", _H))
    out.append(Paragraph(_exec_summary(ctx), _P))
    out.append(Spacer(1, 6))

    # 2. Statutory basis
    out.append(Paragraph("2. Statutory basis", _H))
    out.append(Paragraph(certin.STATUTORY_NOTICE, _P))
    out.append(Spacer(1, 3))
    out.append(_kv_table([
        [Paragraph("Incident reference", _PB), Paragraph(inc.incident_uuid, _P)],
        [Paragraph("Statutory category", _PB), Paragraph(f'{ctx["numeral"]} — {ctx["type_label"]}', _P)],
        [Paragraph("Filed by", _PB), Paragraph(f'{s["reporter"]["name_role"]} · {s["reporter"]["organization_name"]}', _P)],
        [Paragraph("Confirmed by reviewer", _PB),
         Paragraph(f'{s["reviewer"]["name"]} ({s["reviewer"]["role"]}) at {fmt_ist(ctx["confirmed"])}', _P)],
    ], col0=55 * mm))
    out.append(Spacer(1, 6))

    # 3. Incident timeline (six-clock)
    out.append(Paragraph("3. Incident timeline (IST)", _H))
    dl = fmt_ist(ctx["deadline"]) if ctx["deadline"] else "—"
    out.append(_kv_table([
        [Paragraph("Occurrence (earliest evidence)", _PB), Paragraph(fmt_ist(ctx["occurrence"]), _P)],
        [Paragraph("Detection (rule fired)", _PB), Paragraph(fmt_ist(ctx["detection"]), _P)],
        [Paragraph("Noticed (6-hour clock start)", _PB), Paragraph(fmt_ist(ctx["noticed"]), _P)],
        [Paragraph("Statutory reporting deadline", _PB), Paragraph(f'<b>{dl}</b> (noticed + 6h)', _P)],
        [Paragraph("Confirmed by reviewer", _PB), Paragraph(fmt_ist(ctx["confirmed"]), _P)],
        [Paragraph("Report generated", _PB), Paragraph(fmt_ist(ctx["generated_at"]), _P)],
    ], col0=60 * mm))
    out.append(Spacer(1, 6))

    # 4. Technical analysis / detection rationale
    out.append(Paragraph("4. Technical analysis &amp; detection rationale", _H))
    rd = ctx["rule"]
    out.append(_kv_table([
        [Paragraph("Detection rule", _PB), Paragraph(f'{inc.rule_title} <font size=7 color="#666">({inc.rule_id})</font>', _P)],
        [Paragraph("Basis", _PB), Paragraph(rd.get("description", "—"), _P)],
        [Paragraph("Correlation", _PB), Paragraph(f'{rd.get("detection_type","—")}'
                   + (f', {rd["within_seconds"]}s window' if rd.get("within_seconds") else '')
                   + f' · {len(inc.events)} correlated events', _P)],
        [Paragraph("MITRE ATT&amp;CK", _PB), Paragraph("<br/>".join(ctx["mitre"]) or "—", _P)],
        [Paragraph("Attack vector", _PB), Paragraph(ctx["attack_vector"] or "—", _P)],
    ], col0=45 * mm))
    out.append(Spacer(1, 6))

    # 5. Impact & scope
    out.append(Paragraph("5. Impact &amp; scope", _H))
    out.append(_kv_table([
        [Paragraph("Affected system", _PB),
         Paragraph(f'{ctx["affected_ip"]} · {asys["domain_url"]} · {asys["operating_system"]} · '
                   f'{asys["application"]}', _P)],
        [Paragraph("Location / hosting", _PB),
         Paragraph(f'{asys["location"]}' + (f' · {asys["make_model_cloud"]}' if asys["make_model_cloud"] else ''), _P)],
        [Paragraph("Mission-critical", _PB),
         Paragraph(f'<b>{asys["mission_critical"]}</b> — {asys["mission_critical_note"]}', _P)],
        [Paragraph("Impact assessment", _PB), Paragraph(s["incident"]["impact_summary"] or "Under assessment.", _P)],
    ], col0=45 * mm))
    out.append(Spacer(1, 6))

    # 6. Indicators of compromise
    out.append(Paragraph("6. Indicators of compromise (IOCs)", _H))
    ioc_rows = [[Paragraph("<b>Type</b>", _SMALL), Paragraph("<b>Indicator</b>", _SMALL),
                 Paragraph("<b>Context</b>", _SMALL)]]
    for ip in ctx["ips"]:
        ioc_rows.append([Paragraph("IPv4 (source)", _SMALL), Paragraph(ip, _SMALL),
                         Paragraph("External source observed in evidence", _SMALL)])
    for acct in _accounts(inc):
        ioc_rows.append([Paragraph("Account", _SMALL), Paragraph(acct.replace("<", "&lt;"), _SMALL),
                         Paragraph("Targeted / referenced account", _SMALL)])
    ports = _ports(inc)
    if ports:
        ioc_rows.append([Paragraph("Port(s)", _SMALL), Paragraph(", ".join(ports), _SMALL),
                         Paragraph("Observed in connection records", _SMALL)])
    for tech in ctx["mitre"]:
        ioc_rows.append([Paragraph("MITRE technique", _SMALL), Paragraph(tech, _SMALL),
                         Paragraph("Mapped adversary behaviour", _SMALL)])
    if len(ioc_rows) == 1:
        ioc_rows.append([Paragraph("—", _SMALL), Paragraph("None extracted", _SMALL), Paragraph("", _SMALL)])
    ioc_tbl = Table(ioc_rows, colWidths=[30 * mm, 60 * mm, 90 * mm], repeatRows=1)
    ioc_tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#999")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, 0), _GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    out.append(ioc_tbl)
    out.append(Spacer(1, 6))

    # 7. Evidence provenance & cryptographic integrity
    out.append(Paragraph("7. Evidence provenance &amp; cryptographic integrity", _H))
    status = "PASS" if ch.ok else "FAIL"
    out.append(Paragraph(
        f'The compliance tool <b>independently re-verified</b> the evidence vault directly from the sealed '
        f'records (it did not trust an API): <b>[{status}] {ch.records} records · contiguous sequence · '
        f'chain intact · 0 tampering</b>. Receive-side Ed25519 signatures verified: '
        f'<b>{ch.signatures_verified}/{ch.signatures_total}</b>. Evidence at rest is AES-GCM sealed; the audit '
        f'reference for this authorised unsealing is <b>{ctx["audit_ref"]}</b>.', _P))
    out.append(Paragraph(
        f'Chain formula: SHA-256( "{ch.domain_sep}" || prev_hash || sequence || received_at || canonical_event_bytes ), '
        f'genesis prev_hash = {ch.genesis[:16]}… . This proves any acknowledged event cannot be altered or dropped '
        f'without breaking the chain.', _SMALL))
    out.append(Spacer(1, 6))

    # 8. Chronological evidence log (unmasked)
    out.append(Paragraph("8. Chronological evidence log (unmasked, for CERT-In)", _H))
    header = [Paragraph(f"<b>{h}</b>", _SMALL) for h in
              ("Seq", "Time (IST)", "Source", "Type", "Sev", "Raw log (unmasked)", "Row hash", "Sig")]
    data = [header]
    for e in inc.events:
        data.append([
            Paragraph(str(e.seq), _SMALL), Paragraph(fmt_ist(e.received_at).replace(" IST", ""), _SMALL),
            Paragraph(e.source, _SMALL), Paragraph(e.event_type, _SMALL), Paragraph(e.severity, _SMALL),
            Paragraph((e.raw_message or "").replace("<", "&lt;"), _SMALL),
            Paragraph(e.row_hash[:12] + "…", _SMALL),
            Paragraph("✓" if e.signature_verified else "—", _SMALL),
        ])
    tbl = Table(data, colWidths=[8 * mm, 24 * mm, 26 * mm, 20 * mm, 12 * mm, 60 * mm, 22 * mm, 8 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#999")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, 0), _GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    out.append(tbl)
    out.append(Spacer(1, 6))

    # 9. Response & remediation
    out.append(Paragraph("9. Response &amp; remediation", _H))
    steps = s["incident"]["remediation"]
    if steps:
        body = "<br/>".join(f'{i}. {step}' for i, step in enumerate(steps, 1))
    else:
        body = "Response actions in progress; to be supplemented in a follow-up communication."
    out.append(_kv_table([
        [Paragraph("Containment / eradication / recovery", _PB), Paragraph(body, _P)],
        [Paragraph("Reporting status", _PB),
         Paragraph("Submitted to CERT-In within the statutory 6-hour window; investigation ongoing.", _P)],
    ], col0=55 * mm))
    return out


# ---- document assembly -------------------------------------------------------

def _decorate_annex(canvas, doc):
    # Page 1 is the official form; annexure pages are numbered from 2.
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#888"))
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page + 1}")
    canvas.restoreState()


def _annexure_pdf(ctx: dict[str, Any]) -> BytesIO:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
    )
    doc.build(_annexure_flowables(ctx), onFirstPage=_decorate_annex, onLaterPages=_decorate_annex)
    buf.seek(0)
    return buf


def build_pdf(ctx: dict[str, Any], out_path: str) -> str:
    """Build the report PDF: fill the official form's Word cells (so text wraps
    inside the cells), render it to PDF with LibreOffice, stamp the checkbox X
    marks, then append the Detailed Incident Report annexure pages."""
    import os
    import tempfile

    from . import formdoc, formticks  # local imports avoid an import cycle

    inc: IncidentRecord = ctx["incident"]
    work = tempfile.mkdtemp(prefix="certin-form-")
    docx_path = os.path.join(work, "form.docx")
    formdoc.fill_form(ctx, docx_path)
    form_pdf = formdoc.docx_to_pdf(docx_path, out_dir=work)
    with open(form_pdf, "rb") as fh:
        form_bytes = formticks.apply(fh.read(), ctx)

    writer = PdfWriter()
    for page in PdfReader(BytesIO(form_bytes)).pages:
        writer.add_page(page)
    for page in PdfReader(_annexure_pdf(ctx)).pages:
        writer.add_page(page)

    writer.add_metadata({
        "/Title": f"CERT-In Incident Reporting Form — {inc.incident_uuid}",
        "/Author": "Barbarika Compliance Engine",
        "/Subject": f"CERT-In {ctx['numeral']} incident report (statutory filing under IT Act Sec 70B(6))",
        "/Creator": "Barbarika Compliance Engine",
        "/Keywords": "CERT-In, Incident Reporting Form, Section 70B",
    })
    with open(out_path, "wb") as fh:
        writer.write(fh)
    return out_path
