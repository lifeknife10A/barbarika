"""Orchestrator: vault → re-verify → unseal → build the report context, then
emit the PDF (authentic form overlay + annexure, + email draft) and/or the
filled editable DOCX of the official form."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import audit, email_draft, formdoc, report, vault
from .submission import load_submission


def _load_context(
    *, db_path: str, submission_path: str, incident: str,
    key_path: str | None, master_key_b64: str | None, rules_dir: str | None,
) -> dict[str, Any]:
    """Read the vault (read-only, re-verifying the chain), unseal the incident,
    load the submission config, and assemble the report context. Records one
    audited disclosure per call."""
    key = vault.load_key(key_path=key_path, master_key_b64=master_key_b64)
    conn = vault.connect(db_path)
    try:
        chain = vault.reverify_chain(conn, key)
        inc = vault.load_incident(conn, key, incident)
    finally:
        conn.close()

    sub = load_submission(submission_path)
    reviewer = f'{sub["reviewer"]["name"]} ({sub["reviewer"]["role"]})'
    audit_ref = audit.record_disclosure(inc.incident_uuid, reviewer, len(inc.events))
    ctx = report.build_context(inc, sub, chain, audit_ref)
    return ctx


def generate_report(
    *, db_path: str, submission_path: str, out_pdf: str,
    incident: str = "latest", key_path: str | None = None,
    master_key_b64: str | None = None, rules_dir: str | None = None,
) -> dict[str, Any]:
    """Produce the submittable PDF: page 1 is the authentic CERT-In form stamped
    with our values, followed by the Detailed Incident Report annexure. Also
    writes the CERT-In email draft."""
    ctx = _load_context(
        db_path=db_path, submission_path=submission_path, incident=incident,
        key_path=key_path, master_key_b64=master_key_b64, rules_dir=rules_dir)
    report.build_pdf(ctx, out_pdf)
    email_path = str(Path(out_pdf).with_suffix("")) + "_email.txt"
    email_draft.write_email(ctx, email_path)
    return {"pdf": out_pdf, "email": email_path, "audit_ref": ctx["audit_ref"],
            "chain": ctx["chain"], "incident": ctx["incident"]}


def generate_form_docx(
    *, db_path: str, submission_path: str, out_docx: str,
    incident: str = "latest", key_path: str | None = None,
    master_key_b64: str | None = None, rules_dir: str | None = None,
) -> dict[str, Any]:
    """Produce the filled, editable DOCX of the authentic CERT-In form (values in
    the form's real table cells). No LibreOffice needed — python-docx only."""
    ctx = _load_context(
        db_path=db_path, submission_path=submission_path, incident=incident,
        key_path=key_path, master_key_b64=master_key_b64, rules_dir=rules_dir)
    formdoc.fill_form(ctx, out_docx)
    return {"docx": out_docx, "audit_ref": ctx["audit_ref"],
            "chain": ctx["chain"], "incident": ctx["incident"]}
