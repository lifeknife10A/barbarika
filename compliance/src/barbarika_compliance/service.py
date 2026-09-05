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


@app.get("/report")
def report(incident: str = Query("latest", description="incident_uuid or 'latest'")):
    db = _require("COMPLIANCE_VAULT_DB")
    sub = _require("COMPLIANCE_SUBMISSION")
    out_dir = tempfile.mkdtemp(prefix="certin-report-")
    out_pdf = os.path.join(out_dir, "report.pdf")
    try:
        res = generate.generate_report(
            db_path=db, submission_path=sub, out_pdf=out_pdf, incident=incident,
            key_path=os.environ.get("SENTRY_KEY_PATH"),
            master_key_b64=os.environ.get("SENTRY_MASTER_KEY"),
            rules_dir=os.environ.get("COMPLIANCE_RULES_DIR"),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    uuid_short = res["incident"].incident_uuid[:8]
    return FileResponse(
        res["pdf"], media_type="application/pdf",
        filename=f"CERT-In_Incident_Report_{uuid_short}.pdf",
    )
