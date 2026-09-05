"""Pydantic models for the ingestion API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# The 20 Annexure I identifiers, mirrored from ../rules so we can validate the
# optional `category` on ingest without a hard import at module load.
CERT_IN_CATEGORIES = {
    "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x",
    "xi", "xii", "xiii", "xiv", "xv", "xvi", "xvii", "xviii", "xix", "xx",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventIn(BaseModel):
    """A minimal inbound event from the primary-server agent.

    `category` + `raw_message` are optional; when both are present the event is
    eligible for rule evaluation on write (see app/detect.py). Timestamps are
    kept distinct (occurred/detected/received) per AGENTS.md rule 6; the Sentry
    host always stamps `received_at` itself.
    """

    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., min_length=1, max_length=128)
    source: str = Field(..., min_length=1, max_length=256)
    severity: str = Field(default="info", max_length=32)
    category: str | None = Field(default=None, description="CERT-In Annexure I id, e.g. 'iii'.")
    occurred_at: datetime | None = None
    detected_at: datetime | None = None
    raw_message: str | None = Field(default=None, max_length=8192)
    payload: dict[str, Any] = Field(default_factory=dict)

    def validate_category(self) -> None:
        if self.category is not None and self.category not in CERT_IN_CATEGORIES:
            raise ValueError(f"unknown CERT-In category: {self.category!r}")


class EventAck(BaseModel):
    status: str = "accepted"
    id: int
    seq: int
    received_at: datetime
    row_hash: str


class EventOut(BaseModel):
    """Event as returned to the dashboard — masked by default."""

    id: int
    seq: int
    event_type: str
    source: str
    severity: str
    category: str | None
    occurred_at: datetime | None
    detected_at: datetime | None
    received_at: datetime
    raw_message: str | None
    payload: dict[str, Any]
    row_hash: str
    masked: bool
    signature_verified: bool = False
    signer_identity: str | None = None
    signer_pubkey: str | None = None


class IncidentOut(BaseModel):
    id: int
    incident_uuid: str
    rule_id: str
    rule_title: str
    category: str
    event_ids: list[int]
    detected_at: datetime
    created_at: datetime


class HostSnapshot(BaseModel):
    """Operational health of a monitored agent host (NOT evidence).

    The agent runs on the host with full local access, so it reports the host's
    own vitals alongside the log stream. These are volatile status pings — Sentry
    keeps only the latest per agent and never seals or hash-chains them (they
    carry no forensic value and would flood the evidence chain).
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(..., min_length=1, max_length=128)
    os: str | None = Field(default=None, max_length=128)
    kernel: str | None = Field(default=None, max_length=128)
    cpu_percent: float | None = None
    mem_used_mb: float | None = None
    mem_total_mb: float | None = None
    load1: float | None = None
    rss_mb: float | None = None
    uptime_s: float | None = None
    agent_version: str | None = Field(default=None, max_length=64)
    egress_mode: str | None = Field(default=None, max_length=64)
    sequence: int | None = None


class HostOut(HostSnapshot):
    received_at: datetime
