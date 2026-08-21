"""Detection integration: evaluate Angela's rules package on each ingested event.

Sentry does NOT own rule logic (that lives in ../rules/, per README). This module
just:

* loads the versioned YAML rules from the rules package on startup;
* keeps a short in-memory window of recent NormalizedEvents per category
  (sequence rules need predecessors, and the window is bounded for the demo);
* re-evaluates the affected category's rules on each write and records any new,
  not-yet-seen match as an incident.

Only the 3 real rules exist in ../rules (Category iii/iv/v). The other 17 CERT-In
categories are schema-only — this module never invents detection for them.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

# Import lazily-friendly names from the rules package.
from barbarika_rules import DetectionRule, NormalizedEvent, evaluate_rule, load_rule

DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "rules" / "rules" / "v1"
)
# Keep at most this many recent events per category in memory for correlation.
_WINDOW_PER_CATEGORY = 500


def rules_dir() -> Path:
    return Path(os.environ.get("BARBARIKA_RULES_DIR", str(DEFAULT_RULES_DIR)))


def load_rules() -> list[DetectionRule]:
    """Load every *.yaml rule; skip unparseable files rather than crash ingest."""
    directory = rules_dir()
    rules: list[DetectionRule] = []
    if not directory.is_dir():
        return rules
    for path in sorted(directory.glob("*.yaml")):
        try:
            rules.append(load_rule(path))
        except Exception:  # noqa: BLE001 - a bad rule file must not break ingest
            continue
    return rules


class Detector:
    """Stateful, thread-safe correlation across recently ingested events."""

    def __init__(self, rules: list[DetectionRule]):
        self._rules = rules
        self._lock = threading.Lock()
        # category -> list[(NormalizedEvent, sentry_event_id)]
        self._window: dict[str, list[tuple[NormalizedEvent, int]]] = {}
        self._seen_signatures: set[str] = set()

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def _normalize(
        self,
        *,
        source: str,
        raw_message: str,
        category: str,
        occurred_at: datetime | None,
        detected_at: datetime | None,
        received_at: datetime,
    ) -> NormalizedEvent:
        occ = occurred_at or received_at
        det = detected_at or received_at
        if det < occ:  # NormalizedEvent enforces detected_at >= occurred_at
            det = occ
        return NormalizedEvent(
            event_id=uuid4(),
            occurred_at=occ,
            detected_at=det,
            source=source,
            raw_message=raw_message,
            category=category,  # type: ignore[arg-type]  (validated by enum)
        )

    def observe(
        self,
        *,
        sentry_event_id: int,
        source: str,
        raw_message: str | None,
        category: str | None,
        occurred_at: datetime | None,
        detected_at: datetime | None,
        received_at: datetime,
    ) -> list[dict]:
        """Add an event to the window and return incident dicts for NEW matches.

        Each incident dict: rule_id, rule_title, category, event_ids (sentry ids),
        detected_at (iso), signature, incident_uuid.
        """
        if not raw_message or not category:
            return []

        norm = self._normalize(
            source=source,
            raw_message=raw_message,
            category=category,
            occurred_at=occurred_at,
            detected_at=detected_at,
            received_at=received_at,
        )

        new_incidents: list[dict] = []
        with self._lock:
            bucket = self._window.setdefault(category, [])
            bucket.append((norm, sentry_event_id))
            if len(bucket) > _WINDOW_PER_CATEGORY:
                del bucket[: len(bucket) - _WINDOW_PER_CATEGORY]

            id_by_uuid: dict[UUID, int] = {n.event_id: sid for n, sid in bucket}
            events = [n for n, _ in bucket]

            for rule in self._rules:
                if rule.category.value != category:
                    continue
                for match in evaluate_rule(rule, events):
                    signature = f"{match.rule_id}:" + ",".join(
                        sorted(str(e) for e in match.event_ids)
                    )
                    if signature in self._seen_signatures:
                        continue
                    self._seen_signatures.add(signature)
                    sentry_ids = [id_by_uuid[e] for e in match.event_ids if e in id_by_uuid]
                    new_incidents.append(
                        {
                            "incident_uuid": str(uuid4()),
                            "rule_id": str(match.rule_id),
                            "rule_title": rule.title,
                            "category": category,
                            "event_ids": sentry_ids,
                            "detected_at": received_at.astimezone(timezone.utc).isoformat(),
                            "signature": signature,
                        }
                    )
        return new_incidents
