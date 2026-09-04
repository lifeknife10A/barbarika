from pathlib import Path

import yaml

from barbarika_rules import NormalizedEvent, evaluate_rule, load_rule

ROOT = Path(__file__).parents[1]
RULE = load_rule(ROOT / "rules/v1/category_v_ransomware_burst.yaml")


def load_fixture(name: str) -> list[NormalizedEvent]:
    with (ROOT / "tests/fixtures" / name).open(encoding="utf-8") as fixture_file:
        payload = yaml.safe_load(fixture_file)
    return [NormalizedEvent.model_validate(item) for item in payload]


def test_attack_fixture_fires_on_write_burst_with_canary_alteration() -> None:
    events = load_fixture("category_v_attack.yaml")

    matches = evaluate_rule(RULE, events)

    assert len(matches) == 1
    assert matches[0].category.value == "v"
    # minimal sufficient evidence: 10 writes (the threshold) + the canary event
    assert len(matches[0].event_ids) == 11
    canary_id = events[-1].event_id
    assert canary_id in matches[0].event_ids


def test_benign_fixture_backup_burst_without_canary_does_not_fire() -> None:
    events = load_fixture("category_v_benign.yaml")

    assert evaluate_rule(RULE, events) == []
