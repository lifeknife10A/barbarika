"""Normalized telemetry schema shared by the agent, rules engine, and Sentry."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator


class CertInCategory(str, Enum):
    """All 20 CERT-In Annexure I incident-category identifiers.

    Membership in this enum means the category is represented in the data model;
    it does not imply that Barbarika has a live detector for that category.
    """

    I = "i"
    II = "ii"
    III = "iii"
    IV = "iv"
    V = "v"
    VI = "vi"
    VII = "vii"
    VIII = "viii"
    IX = "ix"
    X = "x"
    XI = "xi"
    XII = "xii"
    XIII = "xiii"
    XIV = "xiv"
    XV = "xv"
    XVI = "xvi"
    XVII = "xvii"
    XVIII = "xviii"
    XIX = "xix"
    XX = "xx"


NonEmptyText = Annotated[str, Field(min_length=1)]


class NormalizedEvent(BaseModel):
    """Canonical event passed from ingestion into detection and evidence storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    occurred_at: AwareDatetime
    detected_at: AwareDatetime
    source: Annotated[str, Field(min_length=1, max_length=255)]
    raw_message: NonEmptyText
    category: CertInCategory

    @field_validator("source", "raw_message")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def validate_timeline(self) -> Self:
        if self.detected_at < self.occurred_at:
            raise ValueError("detected_at must be at or after occurred_at")
        return self
