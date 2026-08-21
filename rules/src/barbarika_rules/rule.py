"""Typed loader for versioned YAML detection rules."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .schema import CertInCategory


class EventPredicate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_message_regex: str


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    match: EventPredicate
    min_count: int = Field(default=1, ge=1)


class SequenceDetection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["sequence"]
    group_by: Literal["source"]
    within_seconds: int = Field(gt=0)
    steps: tuple[SequenceStep, SequenceStep]


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    rule_id: UUID
    title: str
    status: Literal["experimental", "stable"]
    category: CertInCategory
    description: str
    detection: SequenceDetection


def load_rule(path: str | Path) -> DetectionRule:
    """Load and validate a detection rule from YAML."""

    with Path(path).open(encoding="utf-8") as rule_file:
        payload = yaml.safe_load(rule_file)
    return DetectionRule.model_validate(payload)

