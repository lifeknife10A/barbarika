"""Look up the fired detection rule's verbatim description from rules/rules/v1/*.yaml.

The incident stores the rule_id (a UUID) and rule_title; the human-readable
rationale ("why this is Category X") is the rule's YAML `description`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _default_rules_dir() -> Path:
    repo = Path(__file__).resolve().parents[3]
    return repo / "rules" / "rules" / "v1"


def rule_details(rule_id: str, rules_dir: str | Path | None = None) -> dict[str, Any]:
    """Return {title, description, status, detection_type} for a rule_id, or {}"""
    directory = Path(rules_dir) if rules_dir else _default_rules_dir()
    if not directory.is_dir():
        return {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text())
        except Exception:  # noqa: BLE001
            continue
        if str(data.get("rule_id")) == str(rule_id):
            det = data.get("detection", {}) or {}
            return {
                "title": data.get("title", ""),
                "description": " ".join((data.get("description") or "").split()),
                "status": data.get("status", ""),
                "detection_type": det.get("type", ""),
                "within_seconds": det.get("within_seconds"),
            }
    return {}
