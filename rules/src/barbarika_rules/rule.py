"""Typed loader for versioned YAML detection rules.

`schema_version: 1` originally described a single detection shape: a two-step,
single-source ``sequence``. That is kept byte-for-byte compatible here. Three
more detection *types* are added under the same schema version so Categories
(iv), (v) and (x) can be expressed:

* ``single``      — one event matching a predicate is enough (e.g. a lone SQLi
                    probe in an nginx log -> Category x).
* ``threshold``   — at least ``min_count`` events matching one predicate from one
                    source inside ``within_seconds`` (a volumetric burst).
* ``correlation`` — every ``arm`` satisfied inside one ``within_seconds`` window,
                    in any order, **across different sources** (e.g. an nginx
                    exploit request *and* a file change under the web root ->
                    Category iv). This is the join the ``sequence`` type cannot
                    express because it groups by a single ``source``.

``sequence`` is also generalised from exactly two steps to two-or-more, so the
existing Category (iii) brute-force rule can be extended with a privileged
``sudo`` step in a separate rule without touching the first-slice one.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Literal, Union
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .schema import CertInCategory


class EventPredicate(BaseModel):
    """A test applied to a single :class:`~barbarika_rules.schema.NormalizedEvent`.

    ``raw_message_regex`` matches against the exact log line / event text.
    ``source_regex`` matches against the normalized ``source`` (e.g.
    ``primary-srv-01/nginx`` vs ``primary-srv-01/fim``) — this is what lets a
    ``correlation`` rule tell one arm's telemetry stream from another's. At least
    one of the two must be set; both are combined with AND.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_message_regex: str | None = None
    source_regex: str | None = None

    @field_validator("raw_message_regex", "source_regex")
    @classmethod
    def _compilable(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:  # pragma: no cover - message varies by pattern
                raise ValueError(f"invalid regular expression: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _at_least_one_predicate(self) -> "EventPredicate":
        if self.raw_message_regex is None and self.source_regex is None:
            raise ValueError("EventPredicate needs raw_message_regex and/or source_regex")
        return self


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    match: EventPredicate
    min_count: int = Field(default=1, ge=1)


class SequenceDetection(BaseModel):
    """Ordered phases from one source inside a rolling window.

    Two or more steps. The window is anchored at the terminal (last) step: every
    earlier step must be satisfied, in order, within ``within_seconds`` before it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["sequence"]
    group_by: Literal["source"]
    within_seconds: int = Field(gt=0)
    steps: Annotated[tuple[SequenceStep, ...], Field(min_length=2)]


class SingleDetection(BaseModel):
    """One event matching ``match`` is a hit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["single"]
    match: EventPredicate


class ThresholdDetection(BaseModel):
    """``min_count`` events matching ``match`` from one source in ``within_seconds``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["threshold"]
    group_by: Literal["source"]
    within_seconds: int = Field(gt=0)
    match: EventPredicate
    min_count: int = Field(ge=2)


class CorrelationArm(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    match: EventPredicate
    min_count: int = Field(default=1, ge=1)


class CorrelationDetection(BaseModel):
    """Every arm satisfied inside one ``within_seconds`` window, in any order.

    Unlike ``sequence`` this does **not** group by source, so arms can match
    different telemetry streams (nginx + filesystem) that belong to the same
    CERT-In category.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["correlation"]
    within_seconds: int = Field(gt=0)
    arms: Annotated[tuple[CorrelationArm, ...], Field(min_length=2)]


Detection = Annotated[
    Union[SingleDetection, ThresholdDetection, SequenceDetection, CorrelationDetection],
    Field(discriminator="type"),
]


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    rule_id: UUID
    title: str
    status: Literal["experimental", "stable"]
    category: CertInCategory
    description: str
    detection: Detection


def load_rule(path: str | Path) -> DetectionRule:
    """Load and validate a detection rule from YAML."""

    with Path(path).open(encoding="utf-8") as rule_file:
        payload = yaml.safe_load(rule_file)
    return DetectionRule.model_validate(payload)
