"""Orchestrator: vault → re-verify → unseal → fill official form → PDF (+ email draft)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import audit, email_draft, report, vault
from .submission import load_submission


def generate_report(
    *, db_path: str, submission_path: str, out_pdf: str,
    incident: str = "latest", key_path: str | None = None,
    master_key_b64: str | None = None, rules_dir: str | None = None,
) -> dict[str, Any]:
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
    report.build_pdf(ctx, out_pdf)
    email_path = str(Path(out_pdf).with_suffix("")) + "_email.txt"
    email_draft.write_email(ctx, email_path)

    return {"pdf": out_pdf, "email": email_path, "audit_ref": audit_ref,
            "chain": chain, "incident": inc}
