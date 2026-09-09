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
def report(
    incident: str = Query("latest", description="incident_uuid or 'latest' (single-incident report)"),
    incidents: str | None = Query(
        None, description="comma-separated incident_uuids for one consolidated report "
                          "across a multi-stage compromise (overrides `incident`)"),
    flatten: bool = Query(False, description="true = static locked copy; false = editable form fields"),
):
    """The report PDF: authentic CERT-In form (page 1) + Detailed Incident Report.

    Single incident: ``?incident=<uuid>`` (or 'latest'). Consolidated: pass
    ``?incidents=<uuid1>,<uuid2>,…`` to fold several incidents from the same
    compromise into ONE report — every contributing Incident Type box ticked, one
    timeline anchored to the earliest thing noticed, merged evidence/IOCs.

    Default is EDITABLE (page 1 keeps its real form fields); ``?flatten=true`` for
    a static, locked copy.
    """
    db = _require("COMPLIANCE_VAULT_DB")
    sub = _require("COMPLIANCE_SUBMISSION")
    out_pdf = os.path.join(tempfile.mkdtemp(prefix="certin-report-"), "report.pdf")
    uuid_list = [u.strip() for u in incidents.split(",") if u.strip()] if incidents else []
    try:
        if len(uuid_list) > 1:
            res = generate.generate_combined_report(
                db_path=db, submission_path=sub, out_pdf=out_pdf, incidents=uuid_list,
                flatten=flatten, **_env())
        else:
            res = generate.generate_report(
                db_path=db, submission_path=sub, out_pdf=out_pdf,
                incident=(uuid_list[0] if uuid_list else incident), flatten=flatten, **_env())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    combined = res.get("combined")
    stem = "CERT-In_Consolidated_Report" if combined else "CERT-In_Incident_Report"
    uuid_short = res["incident"].incident_uuid[:8]
    suffix = "_final" if flatten else ""
    return FileResponse(
        res["pdf"], media_type="application/pdf",
        filename=f"{stem}_{uuid_short}{suffix}.pdf",
    )
