"""Audit record for each authorised evidence disclosure (report generation).

Unsealing evidence for a submission is an authorised, audited action (mirrors
the vault's own unmask-is-audited posture). Every report appends a line here and
the PDF cites the returned reference.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _audit_path() -> Path:
    p = os.environ.get("COMPLIANCE_AUDIT_LOG")
    if p:
        return Path(p)
    return Path(__file__).resolve().parents[3] / "compliance" / "audit.log.jsonl"


def record_disclosure(incident_uuid: str, reviewer: str, events_unsealed: int) -> str:
    ref = "AUD-" + uuid.uuid4().hex[:12].upper()
    entry = {
        "audit_ref": ref,
        "at": datetime.now(timezone.utc).isoformat(),
        "action": "annexure_i_report_generated",
        "incident": incident_uuid,
        "reviewer": reviewer,
        "events_unsealed": events_unsealed,
    }
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return ref
