"""FastAPI compliance service — the dashboard 'Incident Report' button calls this.

Config via env:
  COMPLIANCE_VAULT_DB    path to the Sentry vault sqlite file (read-only)
  COMPLIANCE_SUBMISSION  path to submission.toml
  SENTRY_KEY_PATH or SENTRY_MASTER_KEY  the AES key that seals the vault
  COMPLIANCE_RULES_DIR   (optional) rules/rules/v1
"""

from __future__ import annotations

import os
import tempfile

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from . import generate

app = FastAPI(title="Barbarika Compliance", version="0.1.0",
              summary="Fills the official CERT-In Incident Reporting Form from the evidence vault.")


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise HTTPException(status_code=500, detail=f"compliance service misconfigured: {name} not set")
    return v


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "vault": os.environ.get("COMPLIANCE_VAULT_DB", ""),
        "submission_configured": bool(os.environ.get("COMPLIANCE_SUBMISSION")),
    }


def _env():
    return {
        "key_path": os.environ.get("SENTRY_KEY_PATH"),
        "master_key_b64": os.environ.get("SENTRY_MASTER_KEY"),
        "rules_dir": os.environ.get("COMPLIANCE_RULES_DIR"),
    }


@app.get("/report")
def report(incident: str = Query("latest", description="incident_uuid or 'latest'")):
    """The submittable PDF: authentic CERT-In form (page 1) + Detailed Incident Report."""
    db = _require("COMPLIANCE_VAULT_DB")
    sub = _require("COMPLIANCE_SUBMISSION")
    out_pdf = os.path.join(tempfile.mkdtemp(prefix="certin-report-"), "report.pdf")
    try:
        res = generate.generate_report(
            db_path=db, submission_path=sub, out_pdf=out_pdf, incident=incident, **_env())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    uuid_short = res["incident"].incident_uuid[:8]
    return FileResponse(
        res["pdf"], media_type="application/pdf",
        filename=f"CERT-In_Incident_Report_{uuid_short}.pdf",
    )


@app.get("/report.docx")
def report_docx(incident: str = Query("latest", description="incident_uuid or 'latest'")):
    """The editable Word copy: the authentic CERT-In form filled into its real cells.

    No LibreOffice dependency — python-docx only. The engineer can review/adjust the
    wording and 'Save as PDF' from Word if they want a document-rendered version.
    """
    db = _require("COMPLIANCE_VAULT_DB")
    sub = _require("COMPLIANCE_SUBMISSION")
    out_docx = os.path.join(tempfile.mkdtemp(prefix="certin-form-"), "form.docx")
    try:
        res = generate.generate_form_docx(
            db_path=db, submission_path=sub, out_docx=out_docx, incident=incident, **_env())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    uuid_short = res["incident"].incident_uuid[:8]
    return FileResponse(
        res["docx"],
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=f"CERT-In_Incident_Form_{uuid_short}.docx",
    )
