"""Deterministic evaluator for versioned YAML detection rules.

Pure and side-effect free: it takes a list of :class:`NormalizedEvent` and
returns :class:`RuleMatch` objects. No I/O, no wall-clock reads — every time
decision is made from the events' own ``occurred_at``. ``evaluate_rule`` is the
single public entry point; it dispatches on ``rule.detection.type``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .rule import (
    CorrelationDetection,
    DetectionRule,
    EventPredicate,
    SequenceDetection,
    SequenceStep,
    SingleDetection,
    ThresholdDetection,
)
from .schema import CertInCategory, NormalizedEvent


class RuleMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: UUID
    category: CertInCategory
    event_ids: tuple[UUID, ...]


def evaluate_rule(rule: DetectionRule, events: list[NormalizedEvent]) -> list[RuleMatch]:
    """Return every match of ``rule`` over ``events`` without mutating them."""

    detection = rule.detection
    if isinstance(detection, SequenceDetection):
        return _evaluate_sequence(rule, detection, events)
    if isinstance(detection, SingleDetection):
        return _evaluate_single(rule, detection, events)
    if isinstance(detection, ThresholdDetection):
        return _evaluate_threshold(rule, detection, events)
    if isinstance(detection, CorrelationDetection):
        return _evaluate_correlation(rule, detection, events)
    raise TypeError(f"unsupported detection type: {type(detection)!r}")  # pragma: no cover


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _predicate_matches(predicate: EventPredicate, event: NormalizedEvent) -> bool:
    if predicate.raw_message_regex is not None and not re.search(
        predicate.raw_message_regex, event.raw_message
    ):
        return False
    if predicate.source_regex is not None and not re.search(
        predicate.source_regex, event.source
    ):
        return False
    return True


def _in_category(rule: DetectionRule, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    return [event for event in events if event.category == rule.category]


def _ordered(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    return sorted(events, key=lambda event: (event.occurred_at, str(event.event_id)))


def _match(rule: DetectionRule, ordered_events: list[NormalizedEvent]) -> RuleMatch:
    return RuleMatch(
        rule_id=rule.rule_id,
        category=rule.category,
        event_ids=tuple(event.event_id for event in ordered_events),
    )


# --------------------------------------------------------------------------- #
# sequence  (generalised from the original two-step evaluator)
# --------------------------------------------------------------------------- #
def _assign_prefix(
    segment: list[NormalizedEvent], steps: tuple[SequenceStep, ...]
) -> list[NormalizedEvent] | None:
    """Greedily assign ``segment`` (time-ordered) to ``steps`` in order.

    Returns the consumed events if every step reached its ``min_count``, else
    ``None``. For a single step this is exactly "at least min_count events match",
    which is why the two-step behaviour is unchanged.
    """

    index = 0
    counts = [0] * len(steps)
    used: list[list[NormalizedEvent]] = [[] for _ in steps]
    for event in segment:
        while index < len(steps) and not _predicate_matches(steps[index].match, event):
            if counts[index] >= steps[index].min_count:
                index += 1
            else:
                break
        if index >= len(steps):
            break
        if _predicate_matches(steps[index].match, event):
            counts[index] += 1
            used[index].append(event)
    if all(counts[i] >= steps[i].min_count for i in range(len(steps))):
        return [event for bucket in used for event in bucket]
    return None


def _evaluate_sequence(
    rule: DetectionRule, detection: SequenceDetection, events: list[NormalizedEvent]
) -> list[RuleMatch]:
    steps = detection.steps
    terminal_step = steps[-1]
    window = timedelta(seconds=detection.within_seconds)

    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in _in_category(rule, events):
        grouped[event.source].append(event)

    matches: list[RuleMatch] = []
    for group_events in grouped.values():
        ordered = _ordered(group_events)
        for terminal_index, terminal_event in enumerate(ordered):
            if not _predicate_matches(terminal_step.match, terminal_event):
                continue
            window_start = terminal_event.occurred_at - window
            segment = [
                event
                for event in ordered[:terminal_index]
                if window_start <= event.occurred_at <= terminal_event.occurred_at
            ]
            prefix = _assign_prefix(segment, steps[:-1])
            if prefix is None:
                continue
            matches.append(_match(rule, [*prefix, terminal_event]))
    return matches


# --------------------------------------------------------------------------- #
# single
# --------------------------------------------------------------------------- #
def _evaluate_single(
    rule: DetectionRule, detection: SingleDetection, events: list[NormalizedEvent]
) -> list[RuleMatch]:
    return [
        _match(rule, [event])
        for event in _ordered(_in_category(rule, events))
        if _predicate_matches(detection.match, event)
    ]


# --------------------------------------------------------------------------- #
# threshold
# --------------------------------------------------------------------------- #
def _evaluate_threshold(
    rule: DetectionRule, detection: ThresholdDetection, events: list[NormalizedEvent]
) -> list[RuleMatch]:
    window = timedelta(seconds=detection.within_seconds)
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in _in_category(rule, events):
        if _predicate_matches(detection.match, event):
            grouped[event.source].append(event)

    matches: list[RuleMatch] = []
    for group_events in grouped.values():
        ordered = _ordered(group_events)
        start = 0
        while start < len(ordered):
            end = start
            while (
                end < len(ordered)
                and ordered[end].occurred_at - ordered[start].occurred_at <= window
            ):
                end += 1
            burst = ordered[start:end]
            if len(burst) >= detection.min_count:
                # Cite the earliest min_count events so the match set is stable as
                # the burst grows across successive evaluations (see correlation).
                matches.append(_match(rule, burst[: detection.min_count]))
                start = end  # one match per burst
            else:
                start += 1
    return matches


# --------------------------------------------------------------------------- #
# correlation
# --------------------------------------------------------------------------- #
def _evaluate_correlation(
    rule: DetectionRule, detection: CorrelationDetection, events: list[NormalizedEvent]
) -> list[RuleMatch]:
    window = timedelta(seconds=detection.within_seconds)
    candidates = _ordered(_in_category(rule, events))

    arm_hits: list[list[NormalizedEvent]] = [
        [event for event in candidates if _predicate_matches(arm.match, event)]
        for arm in detection.arms
    ]
    if any(len(hits) < arm.min_count for arm, hits in zip(detection.arms, arm_hits)):
        return []

    union: dict[UUID, NormalizedEvent] = {
        event.event_id: event for hits in arm_hits for event in hits
    }
    anchors = _ordered(list(union.values()))

    matches: list[RuleMatch] = []
    covered_until = None
    for anchor in anchors:
        start = anchor.occurred_at
        end = start + window
        if covered_until is not None and start <= covered_until:
            continue
        contributing: dict[UUID, NormalizedEvent] = {}
        satisfied = True
        for arm, hits in zip(detection.arms, arm_hits):
            in_window = _ordered([e for e in hits if start <= e.occurred_at <= end])
            if len(in_window) < arm.min_count:
                satisfied = False
                break
            # Cite exactly the earliest min_count events per arm so the match set
            # (and therefore the dedup signature the detector computes) is stable
            # once the threshold is first crossed — later events in the same
            # burst do not spawn a second, superset incident.
            for event in in_window[: arm.min_count]:
                contributing[event.event_id] = event
        if satisfied:
            matches.append(_match(rule, _ordered(list(contributing.values()))))
            covered_until = end
    return matches
