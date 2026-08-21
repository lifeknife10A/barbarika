from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from barbarika_rules import CertInCategory, NormalizedEvent


VALID_EVENT = {
    "event_id": "20000000-0000-4000-8000-000000000001",
    "occurred_at": "2026-08-22T12:00:00Z",
    "detected_at": "2026-08-22T12:00:01Z",
    "source": "primary-srv-01/auth.log",
    "raw_message": "sshd[6001]: Failed password for admin from 203.0.113.9 port 53001 ssh2",
    "category": "iii",
}


def test_normalized_event_has_exact_canonical_fields() -> None:
    event = NormalizedEvent.model_validate(VALID_EVENT)

    assert set(NormalizedEvent.model_fields) == {
        "event_id",
        "occurred_at",
        "detected_at",
        "source",
        "raw_message",
        "category",
    }
    assert event.event_id == UUID(VALID_EVENT["event_id"])
    assert event.occurred_at == datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def test_all_twenty_categories_are_represented_in_schema() -> None:
    assert len(CertInCategory) == 20


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("occurred_at", "2026-08-22T12:00:00"),
        ("detected_at", "2026-08-22T12:00:01"),
    ],
)
def test_normalized_event_rejects_timezone_naive_timestamps(
    field: str, invalid_value: str
) -> None:
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate({**VALID_EVENT, field: invalid_value})


def test_normalized_event_rejects_detection_before_occurrence() -> None:
    with pytest.raises(ValidationError, match="detected_at must be at or after occurred_at"):
        NormalizedEvent.model_validate(
            {**VALID_EVENT, "detected_at": "2026-08-22T11:59:59Z"}
        )
