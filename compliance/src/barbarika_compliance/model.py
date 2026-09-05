"""Dataclasses assembled from the vault for the report template."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EventEvidence:
    id: int
    seq: int
    event_type: str
    source: str
    severity: str
    category: str | None
    occurred_at: str | None
    detected_at: str | None
    received_at: str
    raw_message: str | None       # UNMASKED (unsealed from the vault)
    payload: dict[str, Any]       # UNMASKED
    row_hash: str
    prev_hash: str
    signature_verified: bool
    signer_identity: str | None
    signer_pubkey: str | None


@dataclass
class ChainAttestation:
    ok: bool
    records: int
    message: str                  # e.g. "[PASS] N records | contiguous sequence | chain intact"
    genesis: str = ""
    domain_sep: str = ""
    signatures_verified: int = 0
    signatures_total: int = 0


@dataclass
class IncidentRecord:
    incident_uuid: str
    rule_id: str
    rule_title: str
    category: str | None
    event_ids: list[int]
    detected_at: str | None
    created_at: str | None
    events: list[EventEvidence] = field(default_factory=list)
