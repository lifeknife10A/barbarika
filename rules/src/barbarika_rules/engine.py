"""Small deterministic evaluator for the first sequence-rule vertical slice."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .rule import DetectionRule
from .schema import CertInCategory, NormalizedEvent


class RuleMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: UUID
    category: CertInCategory
    event_ids: tuple[UUID, ...]


def evaluate_rule(rule: DetectionRule, events: list[NormalizedEvent]) -> list[RuleMatch]:
    """Return sequence matches without mutating the evidence events.

    The current schema version defines a two-step sequence. Each terminal event
    is evaluated against earlier events from the same normalized source inside
    the configured inclusive time window.
    """

    first_step, terminal_step = rule.detection.steps
    first_pattern = re.compile(first_step.match.raw_message_regex)
    terminal_pattern = re.compile(terminal_step.match.raw_message_regex)
    window = timedelta(seconds=rule.detection.within_seconds)

    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.category == rule.category:
            grouped[event.source].append(event)

    matches: list[RuleMatch] = []
    for group_events in grouped.values():
        ordered = sorted(group_events, key=lambda event: (event.occurred_at, str(event.event_id)))
        for terminal_index, terminal_event in enumerate(ordered):
            if not terminal_pattern.search(terminal_event.raw_message):
                continue

            window_start = terminal_event.occurred_at - window
            predecessors = [
                event
                for event in ordered[:terminal_index]
                if window_start <= event.occurred_at <= terminal_event.occurred_at
                and first_pattern.search(event.raw_message)
            ]
            if len(predecessors) < first_step.min_count:
                continue

            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    event_ids=tuple(
                        event.event_id for event in (*predecessors, terminal_event)
                    ),
                )
            )

    return matches

