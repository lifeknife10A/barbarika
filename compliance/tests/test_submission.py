"""Submission-config loading + validation."""

from __future__ import annotations

import pytest

from barbarika_compliance.submission import load_submission


def test_loads_and_merges_defaults(submission_toml):
    sub = load_submission(submission_toml)
    assert sub["reporter"]["name_role"].startswith("Priya Shah")
    assert sub["reporter"]["email"] == "ciso@meridianfinserv.in"
    assert sub["reviewer"]["name"] == "Priya Shah"
    # A field omitted from the TOML still resolves to its default.
    assert sub["affected_system"]["isp"] == ""
    assert sub["incident"]["confirmed_at"] == ""


def test_example_config_is_valid(tmp_path):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "config" / "submission.example.toml"
    sub = load_submission(example)
    assert sub["recipients"]["to"] == "incident@cert-in.org.in"
    assert len(sub["incident"]["remediation"]) >= 1


def test_missing_required_field_raises(tmp_path):
    p = tmp_path / "bad.toml"
    # Missing reporter.email and reviewer.name.
    p.write_text(
        '[reporter]\n'
        'name_role = "Someone"\n'
        '[reviewer]\n'
        'role = "CISO"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        load_submission(str(p))
    msg = str(exc.value)
    assert "reporter.email" in msg
    assert "reviewer.name" in msg
