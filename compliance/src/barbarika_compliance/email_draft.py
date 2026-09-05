"""Compose the CERT-In submission email DRAFT. Never sends — a human dispatches it."""

from __future__ import annotations

from typing import Any

from . import certin
from .report import fmt_ist


def compose(ctx: dict[str, Any]) -> str:
    inc = ctx["incident"]
    s = ctx["submission"]
    lines = [
        "*** DRAFT — NOT SENT. The reporting officer must review and dispatch this from their own mail client. ***",
        "",
        f'To: {s["recipients"]["to"]}',
        f'Cc: {s["recipients"]["cc"]}',
        f'Subject: CERT-In Incident Report — {ctx["numeral"]} — {s["reporter"]["organization_name"]} '
        f'(within 6h, IT Act Sec 70B(6))',
        "",
        "Respected CERT-In Team,",
        "",
        f'This is a mandatory incident report under sub-section (6) of section 70B of the IT Act, 2000, '
        f'per CERT-In Directions No. 20(3)/2022-CERT-In dated 28 April 2022.',
        "",
        f'1. Reporting organisation : {s["reporter"]["organization_name"]}',
        f'2. Reporting officer       : {s["reporter"]["name_role"]} ({s["reporter"]["email"]}, {s["reporter"]["contact_no"]})',
        f'3. Incident classification : {ctx["numeral"]} — {ctx["type_label"]}',
        f'4. Noticed at              : {fmt_ist(ctx["noticed"])}  (6-hour deadline: {fmt_ist(ctx["deadline"]) if ctx["deadline"] else "—"})',
        f'5. Occurrence / Detection  : {fmt_ist(ctx["occurrence"])} / {fmt_ist(ctx["detection"])}',
        f'6. Affected system         : {ctx["affected_ip"]} — {s["affected_system"]["operating_system"]} '
        f'({s["affected_system"]["domain_url"]})',
        f'7. Attacker IOCs (IP)      : {", ".join(ctx["ips"]) or "—"}',
        f'8. Impact                  : {s["incident"]["impact_summary"]}',
        "9. Remedial measures       :",
    ]
    for i, step in enumerate(s["incident"]["remediation"], 1):
        lines.append(f"     {i}. {step}")
    lines += [
        "",
        f'10. Evidence integrity     : {ctx["chain"].message}; Ed25519 signatures '
        f'{ctx["chain"].signatures_verified}/{ctx["chain"].signatures_total} verified; '
        f'independently re-verified from the sealed vault (audit ref {ctx["audit_ref"]}).',
        "",
        f'The completed CERT-In Incident Reporting Form (Annexure) is attached: '
        f'CERT-In_Incident_Report_{inc.incident_uuid[:8]}.pdf',
        "",
        "Regards,",
        f'{s["reviewer"]["name"]}, {s["reviewer"]["role"]}',
        f'{s["reporter"]["organization_name"]}',
        "",
        f'(CERT-In channels — email: {certin.REPORTING_CHANNEL["email"]}, '
        f'phone: {certin.REPORTING_CHANNEL["phone"]}, fax: {certin.REPORTING_CHANNEL["fax"]})',
    ]
    return "\n".join(lines)


def write_email(ctx: dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(compose(ctx))
    return path
