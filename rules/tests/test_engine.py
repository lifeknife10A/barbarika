"""Focused evaluator tests for the detection types added under schema_version 1.

The two-step ``sequence`` path is covered end-to-end by test_category_iii.py; the
first test here pins the invariant that generalising the evaluator to N steps did
not change two-step output.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from barbarika_rules import DetectionRule, NormalizedEvent, evaluate_rule

BASE = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)


def _event(n: int, source: str, message: str, category: str = "x", offset_s: float = 0.0) -> NormalizedEvent:
    occurred = BASE + timedelta(seconds=offset_s)
    return NormalizedEvent(
        event_id=UUID(int=n),
        occurred_at=occurred,
        detected_at=occurred,
        source=source,
        raw_message=message,
        category=category,  # type: ignore[arg-type]
    )


def _rule(detection: dict, category: str = "x") -> DetectionRule:
    return DetectionRule.model_validate(
        {
            "schema_version": 1,
            "rule_id": "00000000-0000-4000-8000-00000000ffff",
            "title": "t",
            "status": "experimental",
            "category": category,
            "description": "d",
            "detection": detection,
        }
    )


def test_two_step_sequence_output_is_unchanged() -> None:
    rule = _rule(
        {
            "type": "sequence",
            "group_by": "source",
            "within_seconds": 60,
            "steps": [
                {"name": "a", "match": {"raw_message_regex": "fail"}, "min_count": 3},
                {"name": "b", "match": {"raw_message_regex": "ok"}},
            ],
        },
        category="iii",
    )
    events = [
        _event(1, "h/auth", "fail", "iii", 0),
        _event(2, "h/auth", "fail", "iii", 5),
        _event(3, "h/auth", "fail", "iii", 10),
        _event(4, "h/auth", "ok", "iii", 15),
    ]
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].event_ids == tuple(e.event_id for e in events)


def test_sequence_respects_the_window_anchored_at_the_terminal_step() -> None:
    rule = _rule(
        {
            "type": "sequence",
            "group_by": "source",
            "within_seconds": 30,
            "steps": [
                {"name": "a", "match": {"raw_message_regex": "fail"}, "min_count": 2},
                {"name": "b", "match": {"raw_message_regex": "ok"}},
            ],
        },
        category="iii",
    )
    events = [
        _event(1, "h/auth", "fail", "iii", 0),
        _event(2, "h/auth", "fail", "iii", 5),
        _event(3, "h/auth", "ok", "iii", 40),  # 40s after first fail -> out of window
    ]
    assert evaluate_rule(rule, events) == []


def test_single_emits_one_match_per_matching_event() -> None:
    rule = _rule({"type": "single", "match": {"raw_message_regex": "sqlmap"}})
    events = [
        _event(1, "h/nginx", "GET / sqlmap"),
        _event(2, "h/nginx", "GET / firefox"),
        _event(3, "h/nginx", "GET / sqlmap"),
    ]
    matches = evaluate_rule(rule, events)
    assert [m.event_ids for m in matches] == [(UUID(int=1),), (UUID(int=3),)]


def test_single_source_regex_is_anded_with_message_regex() -> None:
    rule = _rule({"type": "single", "match": {"raw_message_regex": "x", "source_regex": "/nginx$"}})
    events = [_event(1, "h/auth", "x"), _event(2, "h/nginx", "x")]
    assert [m.event_ids for m in evaluate_rule(rule, events)] == [(UUID(int=2),)]


def test_threshold_fires_once_per_burst_and_ignores_sparse_traffic() -> None:
    rule = _rule(
        {
            "type": "threshold",
            "group_by": "source",
            "within_seconds": 10,
            "match": {"raw_message_regex": "hit"},
            "min_count": 5,
        }
    )
    burst = [_event(i, "h/nginx", "hit", offset_s=i) for i in range(1, 7)]  # 6 in 6s
    sparse = [_event(10 + i, "h/nginx", "hit", offset_s=100 + i * 40) for i in range(3)]
    matches = evaluate_rule(rule, burst + sparse)
    assert len(matches) == 1
    assert len(matches[0].event_ids) == 5  # earliest min_count, stable as burst grows


def test_correlation_needs_every_arm_inside_one_window() -> None:
    detection = {
        "type": "correlation",
        "within_seconds": 60,
        "arms": [
            {"name": "http", "match": {"source_regex": "/nginx$", "raw_message_regex": "exploit"}},
            {"name": "file", "match": {"source_regex": "/fim$", "raw_message_regex": "^FIM WRITE"}},
        ],
    }
    rule = _rule(detection, category="iv")
    hit = [
        _event(1, "h/nginx", "exploit", "iv", 0),
        _event(2, "h/fim", "FIM WRITE /var/www/x", "iv", 10),
    ]
    assert len(evaluate_rule(rule, hit)) == 1

    miss = [
        _event(1, "h/nginx", "exploit", "iv", 0),
        _event(2, "h/fim", "FIM WRITE /var/www/x", "iv", 120),  # outside 60s
    ]
    assert evaluate_rule(rule, miss) == []

    one_arm_only = [_event(1, "h/nginx", "exploit", "iv", 0)]
    assert evaluate_rule(rule, one_arm_only) == []
