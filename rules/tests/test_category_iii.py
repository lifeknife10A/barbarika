from pathlib import Path

import yaml

from barbarika_rules import NormalizedEvent, evaluate_rule, load_rule


ROOT = Path(__file__).parents[1]
RULE = load_rule(ROOT / "rules/v1/category_iii_ssh_bruteforce.yaml")


def load_fixture(name: str) -> list[NormalizedEvent]:
    with (ROOT / "tests/fixtures" / name).open(encoding="utf-8") as fixture_file:
        payload = yaml.safe_load(fixture_file)
    return [NormalizedEvent.model_validate(item) for item in payload]


def test_attack_fixture_fires_after_ten_failures_and_a_success() -> None:
    events = load_fixture("category_iii_attack.yaml")

    matches = evaluate_rule(RULE, events)

    assert len(matches) == 1
    assert matches[0].category.value == "iii"
    assert matches[0].event_ids == tuple(event.event_id for event in events)


def test_benign_fixture_outside_sixty_second_window_does_not_fire() -> None:
    events = load_fixture("category_iii_benign.yaml")

    assert evaluate_rule(RULE, events) == []

