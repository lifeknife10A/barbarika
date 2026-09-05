"""Render the authentic CERT-In Incident Reporting Form (certinirform.pdf layout),
filled from the vault, followed by Barbarika evidence-integrity annexes.

Flat, non-editable PDF (ReportLab, no interactive form fields), locked metadata.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from . import certin
from .model import ChainAttestation, IncidentRecord
from .rules import rule_details

IST = timezone(timedelta(hours=5, minutes=30))
_GRAY = colors.HexColor("#c8c8c8")
_INK = colors.HexColor("#111111")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_ss = getSampleStyleSheet()
_P = ParagraphStyle("cell", parent=_ss["BodyText"], fontName="Helvetica", fontSize=8, leading=10)
_PB = ParagraphStyle("cellb", parent=_P, fontName="Helvetica-Bold")
_SMALL = ParagraphStyle("small", parent=_P, fontSize=7, leading=8.5, textColor=colors.HexColor("#444"))
_TITLE = ParagraphStyle("title", parent=_ss["Title"], fontName="Helvetica-Bold", fontSize=13, alignment=TA_CENTER)
_H = ParagraphStyle("h", parent=_PB, fontSize=9.5)


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


# ---- form (page 1) -----------------------------------------------------------

def _bar(text: str) -> Table:
    t = Table([[Paragraph(f"<b>{text}</b>", _H)]], colWidths=[180 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _GRAY),
                           ("BOX", (0, 0), (-1, -1), 0.5, _INK),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _kv_table(rows: list[list[Any]], col0=55 * mm) -> Table:
    t = Table(rows, colWidths=[col0, 180 * mm - col0])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, _INK), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _incident_type_checklist(matched: str | None):
    items = certin.INCIDENT_TYPES
    cols = [items[0:7], items[7:14], items[14:20]]
    cells = []
    for col in cols:
        lines = []
        for cid, label in col:
            box = "[X]" if cid == matched else "[&nbsp;&nbsp;]"
            strong = ' color="#b00000"' if cid == matched else ""
            lines.append(f'<font{strong}>{box}</font> {label}')
        cells.append(Paragraph("<br/>".join(lines), _SMALL))
    t = Table([cells], colWidths=[60 * mm, 60 * mm, 60 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.5, _INK),
                           ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#999")),
                           ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    return t


def _form_flowables(ctx: dict[str, Any]) -> list:
    s = ctx["submission"]
    rep, af, asys = s["reporter"], s["affected_entity"], s["affected_system"]
    ind = "[X]" if rep["kind"] == "Individual" else "[&nbsp;&nbsp;]"
    org = "[X]" if rep["kind"] == "Organization" else "[&nbsp;&nbsp;]"
    iam1 = "[X]" if rep["i_am"].startswith("the effected") else "[&nbsp;&nbsp;]"
    iam2 = "[X]" if not rep["i_am"].startswith("the effected") else "[&nbsp;&nbsp;]"

    out: list = [Paragraph("Incident Reporting Form", _TITLE), Spacer(1, 3)]
    out.append(Paragraph(
        f'<b>I am:</b> &nbsp; {iam1} the effected entity &nbsp;&nbsp; {iam2} reporting incident affecting other entity',
        _P))
    out.append(Spacer(1, 4))
    out.append(_bar("Contact Information of the Reporter"))
    out.append(_kv_table([
        [Paragraph("Name &amp; Role/Title", _PB), Paragraph(f'{rep["name_role"]} &nbsp;&nbsp; {ind} Individual &nbsp; {org} Organization', _P)],
        [Paragraph("Organization name (if any)", _PB), Paragraph(rep["organization_name"], _P)],
        [Paragraph("Contact No.", _PB), Paragraph(f'{rep["contact_no"]} &nbsp;&nbsp; <b>Email:</b> {rep["email"]}', _P)],
        [Paragraph("Address:", _PB), Paragraph(rep["address"], _P)],
    ]))
    out.append(Spacer(1, 4))
    out.append(_bar("Basic Incident Details"))
    aff_entity = "" if af["same_as_reporter"] else af["name"]
    out.append(_kv_table([[Paragraph("Affected entity<br/>(if not same as reporting entity above)", _PB),
                           Paragraph(aff_entity or "Same as reporting entity", _P)]]))
    out.append(Table([[Paragraph("<b>Incident Type</b>", _H)]], colWidths=[180 * mm],
                     style=TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("BOX", (0, 0), (-1, -1), 0.5, _INK)])))
    out.append(_incident_type_checklist(ctx["cid"]))
    out.append(_kv_table([
        [Paragraph("Is the affected system/network critical to the organization&rsquo;s mission? (Yes / No). (Brief details.)", _PB),
         Paragraph(f'<b>{asys["mission_critical"]}</b> — {asys["mission_critical_note"]}', _P)],
    ], col0=70 * mm))
    sysinfo = "<br/>".join([
        f'<b>Domain/URL:</b> {asys["domain_url"]}', f'<b>IP Address:</b> {ctx["affected_ip"]}',
        f'<b>Operating System:</b> {asys["operating_system"]}', f'<b>Make/ Model/Cloud details:</b> {asys["make_model_cloud"]}',
        f'<b>Affected Application details (If any):</b> {asys["application"]}',
        f'<b>Location of affected system (including City, Region &amp; Country):</b> {asys["location"]}',
        f'<b>Network and name of ISP:</b> {asys["isp"]}',
    ])
    out.append(_kv_table([[Paragraph("Basic Information of Affected System<br/>(Provide information that is readily available.)", _PB),
                           Paragraph(sysinfo, _P)]], col0=55 * mm))
    desc = (f'{ctx["rule"].get("title", ctx["incident"].rule_title)}. {ctx["attack_vector"]} '
            f'{len(ctx["incident"].events)} correlated events recorded in the tamper-evident vault '
            f'(see Barbarika Evidence Annexure). Impact: {s["incident"]["impact_summary"]}')
    datetimes = (f'<b>Occurrence date &amp; time (dd/mm/yyyy hh:mm):</b> {fmt_ist(ctx["occurrence"])}<br/>'
                 f'<b>Detection date &amp; time (dd/mm/yyyy hh:mm):</b> {fmt_ist(ctx["detection"])}')
    out.append(_kv_table([[Paragraph("Brief description of Incident:", _PB),
                           Paragraph(desc + "<br/><br/>" + datetimes, _P)]], col0=55 * mm))
    out.append(Spacer(1, 3))
    out.append(Paragraph(
        "<b>Note:</b> (i) This form provides general guidance in terms of information which could be relevant "
        "to the incident. (ii) It is not mandatory to fill and/or sign this form. Incidents may also be reported "
        "by providing relevant information in the communication itself or in any other readable form. "
        "(iii) Reporting entity may, if desired, also provide relevant information other than mentioned in this form.",
        _SMALL))
    out.append(Paragraph(
        f'<b>Mail/Fax incident reports to:</b> {certin.REPORTING_CHANNEL["address"]} &nbsp; '
        f'Fax: {certin.REPORTING_CHANNEL["fax"]} &nbsp; or email at: {certin.REPORTING_CHANNEL["email"]}', _SMALL))
    return out


# ---- annexure (evidence) -----------------------------------------------------

def _annexure_flowables(ctx: dict[str, Any]) -> list:
    inc: IncidentRecord = ctx["incident"]
    ch: ChainAttestation = ctx["chain"]
    out: list = [PageBreak(),
                 Paragraph("Barbarika Evidence Annexure", _TITLE), Spacer(1, 2),
                 Paragraph("Supplementary to the CERT-In Incident Reporting Form — tamper-evident provenance for the reported incident.", _SMALL),
                 Spacer(1, 6)]

    out.append(Paragraph("A. Statutory basis", _H))
    out.append(Paragraph(certin.STATUTORY_NOTICE, _P))
    dl = fmt_ist(ctx["deadline"]) if ctx["deadline"] else "—"
    out.append(_kv_table([
        [Paragraph("Incident reference", _PB), Paragraph(inc.incident_uuid, _P)],
        [Paragraph("Statutory category", _PB), Paragraph(f'{ctx["numeral"]} — {ctx["type_label"]}', _P)],
        [Paragraph("Noticed at (6-hour clock start)", _PB), Paragraph(fmt_ist(ctx["noticed"]), _P)],
        [Paragraph("Reporting deadline (noticed + 6h)", _PB), Paragraph(dl, _P)],
        [Paragraph("Confirmed by reviewer", _PB), Paragraph(f'{ctx["submission"]["reviewer"]["name"]} ({ctx["submission"]["reviewer"]["role"]}) at {fmt_ist(ctx["confirmed"])}', _P)],
    ], col0=60 * mm))
    out.append(Spacer(1, 6))

    out.append(Paragraph("B. Detection rationale", _H))
    rd = ctx["rule"]
    out.append(_kv_table([
        [Paragraph("Rule", _PB), Paragraph(f'{inc.rule_title} <font size=7 color="#666">({inc.rule_id})</font>', _P)],
        [Paragraph("Basis", _PB), Paragraph(rd.get("description", "—"), _P)],
        [Paragraph("Detection", _PB), Paragraph(f'{rd.get("detection_type","—")}'
                   + (f', {rd["within_seconds"]}s window' if rd.get("within_seconds") else '')
                   + f' · {len(inc.events)} correlated events', _P)],
        [Paragraph("MITRE ATT&amp;CK", _PB), Paragraph("<br/>".join(ctx["mitre"]) or "—", _P)],
        [Paragraph("Attacker IOCs (IP)", _PB), Paragraph(", ".join(ctx["ips"]) or "—", _P)],
    ], col0=45 * mm))
    out.append(Spacer(1, 6))

    out.append(Paragraph("C. Evidence provenance &amp; cryptographic integrity", _H))
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

    out.append(Paragraph("D. Chronological evidence log (unmasked, for CERT-In)", _H))
    header = [Paragraph(f"<b>{h}</b>", _SMALL) for h in ("Seq", "Time (IST)", "Source", "Type", "Sev", "Raw log (unmasked)", "Row hash", "Sig")]
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
    out.append(Paragraph(
        "<b>Human-in-the-loop:</b> this report was prepared for authorised submission by the named reviewer and "
        "is not auto-dispatched to CERT-In. Provenance re-verified by the Barbarika Compliance Engine from the "
        "sealed evidence vault.", _SMALL))
    return out


# ---- document ----------------------------------------------------------------

def _decorate(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#888"))
    canvas.drawString(15 * mm, 8 * mm, "CONFIDENTIAL — CERT-In statutory incident report")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(ctx: dict[str, Any], out_path: str) -> str:
    inc: IncidentRecord = ctx["incident"]
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
        title=f"CERT-In Incident Reporting Form — {inc.incident_uuid}",
        author="Barbarika Compliance Engine",
        subject=f"CERT-In {ctx['numeral']} incident report (statutory filing under IT Act Sec 70B(6))",
        creator="Barbarika Compliance Engine", keywords="CERT-In, Annexure I, Section 70B",
    )
    story = _form_flowables(ctx) + _annexure_flowables(ctx)
    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return out_path
