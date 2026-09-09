"""Orchestrator: vault → re-verify → unseal → build the report context, then
emit the report PDF (interactive CERT-In form + Detailed Incident Report annexure)
and the CERT-In email draft."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import audit, email_draft, report, vault
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


def _load_combined_context(
    *, db_path: str, submission_path: str, incidents: list[str],
    key_path: str | None, master_key_b64: str | None, rules_dir: str | None,
) -> dict[str, Any]:
    """Like _load_context but consolidates several incidents from the same
    compromise into one context (re-verifies the chain once, unseals each)."""
    key = vault.load_key(key_path=key_path, master_key_b64=master_key_b64)
    conn = vault.connect(db_path)
    try:
        chain = vault.reverify_chain(conn, key)
        recs = [vault.load_incident(conn, key, uuid) for uuid in incidents]
    finally:
        conn.close()

    sub = load_submission(submission_path)
    reviewer = f'{sub["reviewer"]["name"]} ({sub["reviewer"]["role"]})'
    total_events = sum(len(r.events) for r in recs)
    audit_ref = audit.record_disclosure(
        ",".join(r.incident_uuid for r in recs), reviewer, total_events)
    return report.build_combined_context(recs, sub, chain, audit_ref)


def generate_report(
    *, db_path: str, submission_path: str, out_pdf: str,
    incident: str = "latest", key_path: str | None = None,
    master_key_b64: str | None = None, rules_dir: str | None = None,
    flatten: bool = False,
) -> dict[str, Any]:
    """Produce the report PDF: page 1 is the authentic interactive CERT-In form
    filled from our re-verified data, followed by the Detailed Incident Report
    annexure. Also writes the CERT-In email draft.

    flatten=False (default) keeps page 1 editable so the engineer can tweak a
    detail before filing; flatten=True produces a static, locked copy."""
    ctx = _load_context(
        db_path=db_path, submission_path=submission_path, incident=incident,
        key_path=key_path, master_key_b64=master_key_b64, rules_dir=rules_dir)
    report.build_pdf(ctx, out_pdf, flatten=flatten)
    email_path = str(Path(out_pdf).with_suffix("")) + "_email.txt"
    email_draft.write_email(ctx, email_path)
    return {"pdf": out_pdf, "email": email_path, "audit_ref": ctx["audit_ref"],
            "chain": ctx["chain"], "incident": ctx["incident"]}


def generate_combined_report(
    *, db_path: str, submission_path: str, out_pdf: str,
    incidents: list[str], key_path: str | None = None,
    master_key_b64: str | None = None, rules_dir: str | None = None,
    flatten: bool = False,
) -> dict[str, Any]:
    """One consolidated CERT-In report across several incidents from the same
    compromise: every contributing Incident Type box ticked, one timeline anchored
    to the earliest thing noticed, merged evidence/IOCs. Falls back to the
    single-incident layout automatically when only one incident survives dedup."""
    ctx = _load_combined_context(
        db_path=db_path, submission_path=submission_path, incidents=incidents,
        key_path=key_path, master_key_b64=master_key_b64, rules_dir=rules_dir)
    report.build_pdf(ctx, out_pdf, flatten=flatten)
    email_path = str(Path(out_pdf).with_suffix("")) + "_email.txt"
    email_draft.write_email(ctx, email_path)
    return {"pdf": out_pdf, "email": email_path, "audit_ref": ctx["audit_ref"],
            "chain": ctx["chain"], "incident": ctx["incident"], "combined": ctx.get("combined", False)}
