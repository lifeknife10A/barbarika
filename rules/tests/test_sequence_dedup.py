"""Prefix-event consumption in the sequence evaluator.

A cracked SSH credential reused shortly after (a fresh login to run the Cat iv/v
scripts) must NOT re-fire the brute-force / privesc rules by re-citing the same
original failed-login burst. A genuinely new burst of fresh failures still fires
its own independent match.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from barbarika_rules import NormalizedEvent, evaluate_rule, load_rule

ROOT = Path(__file__).parents[1]
BRUTE = load_rule(ROOT / "rules/v1/category_iii_ssh_bruteforce.yaml")
PRIVESC = load_rule(ROOT / "rules/v1/category_iii_ssh_privilege_escalation.yaml")
BASE = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)

SRC = "primary-srv-01/auth"
FAIL = "sshd[2211]: Failed password for root from 192.168.29.176 port {p} ssh2"
OK = "sshd[2299]: Accepted password for root from 192.168.29.176 port {p} ssh2"
SUDO = "sudo: root : TTY=pts/0 ; COMMAND=/bin/bash"


def _ev(n: int, secs: float, msg: str) -> NormalizedEvent:
    t = BASE + timedelta(seconds=secs)
    return NormalizedEvent(event_id=UUID(int=n), occurred_at=t, detected_at=t,
                           source=SRC, raw_message=msg, category="iii")  # type: ignore[arg-type]


def _fails(start_id: int, start_s: float, n: int = 12) -> list[NormalizedEvent]:
    return [_ev(start_id + i, start_s + i, FAIL.format(p=4000 + i)) for i in range(n)]


# --- Bug: credential reuse over-fires -----------------------------------------

def test_reused_login_does_not_refire_bruteforce() -> None:
    # 12 failures, then THREE successful logins seconds apart (the Cat iii success
    # plus the Cat iv and Cat v scripts re-authenticating with the cracked password).
    events = _fails(1, 0)
    events += [_ev(20, 12, OK.format(p=5000)),   # the real brute-force success
               _ev(21, 15, OK.format(p=5001)),   # Cat iv reuse
               _ev(22, 18, OK.format(p=5002))]   # Cat v reuse
    matches = evaluate_rule(BRUTE, events)
    assert len(matches) == 1                      # was 3 before the fix
    # anchored at the FIRST qualifying terminal (the earliest success)
    assert matches[0].event_ids[-1] == UUID(int=20)


def test_reused_login_does_not_refire_privesc() -> None:
    events = _fails(1, 0)
    events += [_ev(20, 12, OK.format(p=5000)), _ev(21, 13, SUDO),   # first intrusion
               _ev(22, 15, OK.format(p=5001)), _ev(23, 16, SUDO)]   # reuse + sudo again
    matches = evaluate_rule(PRIVESC, events)
    assert len(matches) == 1                      # only the first sudo yields a match
    assert matches[0].event_ids[-1] == UUID(int=21)


# --- Preserved: a genuinely new burst still fires -----------------------------

def test_fresh_second_burst_still_fires() -> None:
    events = _fails(1, 0) + [_ev(20, 12, OK.format(p=5000))]        # burst 1 -> match 1
    events += _fails(100, 30) + [_ev(120, 43, OK.format(p=6000))]  # burst 2 (fresh ids) -> match 2
    matches = evaluate_rule(BRUTE, events)
    assert len(matches) == 2                       # the fix must NOT over-suppress real repeats
    assert matches[0].event_ids[-1] == UUID(int=20)
    assert matches[1].event_ids[-1] == UUID(int=120)
    # the second match draws on the fresh failures (100..111), not the consumed first burst
    assert UUID(int=100) in matches[1].event_ids
    assert UUID(int=1) not in matches[1].event_ids


def test_fresh_second_burst_fires_privesc_too() -> None:
    events = _fails(1, 0) + [_ev(20, 12, OK.format(p=5000)), _ev(21, 13, SUDO)]        # intrusion 1
    events += _fails(100, 30) + [_ev(120, 43, OK.format(p=6000)), _ev(121, 44, SUDO)]  # intrusion 2
    matches = evaluate_rule(PRIVESC, events)
    assert len(matches) == 2
    assert matches[1].event_ids[-1] == UUID(int=121)
    assert UUID(int=100) in matches[1].event_ids


def test_single_burst_still_fires_exactly_once() -> None:
    # Regression guard mirroring the existing fixtures: one clean burst -> one match.
    events = _fails(1, 0) + [_ev(20, 12, OK.format(p=5000))]
    assert len(evaluate_rule(BRUTE, events)) == 1
