"""Load the one-time submission config (org / reporter / affected asset / reviewer).

These are the fields a formal filing must state that the vault cannot know
(the reporter's identity, the asset inventory, the human reviewer sign-off).
Everything else is auto-filled from the vault, so the engineer fills this ONCE
and never edits the produced PDF.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

_REQUIRED = [("reporter", "name_role"), ("reporter", "email"), ("reviewer", "name")]

_DEFAULTS: dict[str, dict[str, Any]] = {
    "reporter": {
        "i_am": "the effected entity", "name_role": "", "kind": "Organization",
        "organization_name": "", "contact_no": "", "email": "", "address": "",
    },
    "affected_entity": {"same_as_reporter": True, "name": ""},
    "affected_system": {
        "domain_url": "", "ip_address": "auto", "operating_system": "",
        "make_model_cloud": "", "application": "", "location": "", "isp": "",
        "mission_critical": "Yes", "mission_critical_note": "",
    },
    "incident": {
        "noticed_at": "auto", "confirmed_at": "", "occurrence_override": "",
        "impact_summary": "", "remediation": [],
    },
    "reviewer": {"name": "", "role": "CISO"},
    "recipients": {"to": "incident@cert-in.org.in", "cc": ""},
}


def load_submission(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    merged: dict[str, Any] = {}
    for section, defaults in _DEFAULTS.items():
        merged[section] = {**defaults, **raw.get(section, {})}
    missing = [f"{s}.{k}" for s, k in _REQUIRED if not merged.get(s, {}).get(k)]
    if missing:
        raise ValueError(f"submission config missing required fields: {', '.join(missing)}")
    return merged
