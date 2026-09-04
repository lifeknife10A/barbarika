from pathlib import Path

import yaml

from barbarika_rules import NormalizedEvent, evaluate_rule, load_rule

ROOT = Path(__file__).parents[1]
RULE = load_rule(ROOT / "rules/v1/category_x_appserver_attack.yaml")


def load_fixture(name: str) -> list[NormalizedEvent]:
    with (ROOT / "tests/fixtures" / name).open(encoding="utf-8") as fixture_file:
        payload = yaml.safe_load(fixture_file)
    return [NormalizedEvent.model_validate(item) for item in payload]


def test_attack_fixture_fires_once_on_the_sqli_request() -> None:
    events = load_fixture("category_x_attack.yaml")

    matches = evaluate_rule(RULE, events)

    assert len(matches) == 1
    assert matches[0].category.value == "x"
    assert matches[0].event_ids == (events[1].event_id,)  # only the UNION SELECT line


def test_benign_fixture_catalogue_traffic_does_not_fire() -> None:
    events = load_fixture("category_x_benign.yaml")

    assert evaluate_rule(RULE, events) == []
