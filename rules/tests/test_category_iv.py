from pathlib import Path

import yaml

from barbarika_rules import NormalizedEvent, evaluate_rule, load_rule

ROOT = Path(__file__).parents[1]
RULE = load_rule(ROOT / "rules/v1/category_iv_web_defacement.yaml")


def load_fixture(name: str) -> list[NormalizedEvent]:
    with (ROOT / "tests/fixtures" / name).open(encoding="utf-8") as fixture_file:
        payload = yaml.safe_load(fixture_file)
    return [NormalizedEvent.model_validate(item) for item in payload]


def test_attack_fixture_fires_when_exploit_and_web_root_change_correlate() -> None:
    events = load_fixture("category_iv_attack.yaml")

    matches = evaluate_rule(RULE, events)

    assert len(matches) == 1
    assert matches[0].category.value == "iv"
    # the minimal correlated set: the first exploit request + the web-root write
    assert len(matches[0].event_ids) == 2
    assert events[2].event_id in matches[0].event_ids  # the FIM write
    assert events[0].event_id in matches[0].event_ids  # the earlier exploit probe


def test_benign_fixture_without_exploit_request_does_not_fire() -> None:
    events = load_fixture("category_iv_benign.yaml")

    assert evaluate_rule(RULE, events) == []
