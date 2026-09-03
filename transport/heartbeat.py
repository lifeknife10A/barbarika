"""Heartbeat payload validation and a network-free telemetry watchdog.

``TELEMETRY_LOSS`` is an operational state, not proof of a cyber incident. Recent
high-confidence intrusion evidence can only produce a candidate Category (ii)
disposition that requires human confirmation; this module never confirms or reports
an incident.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import ClassVar, Mapping
from uuid import UUID


HEARTBEAT_INTERVAL_SECONDS = 5.0
MISSED_HEARTBEAT_LIMIT = 3
TELEMETRY_LOSS_AFTER_SECONDS = HEARTBEAT_INTERVAL_SECONDS * MISSED_HEARTBEAT_LIMIT
INTRUSION_CORRELATION_WINDOW_SECONDS = 120.0

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


class HeartbeatValidationError(ValueError):
    """Raised when a heartbeat does not match the shared payload schema."""


class WatchdogState(str, Enum):
    HEALTHY = "HEALTHY"
    TELEMETRY_LOSS = "TELEMETRY_LOSS"


class TelemetryLossDisposition(str, Enum):
    OPERATIONAL_WARNING = "OPERATIONAL_WARNING"
    CANDIDATE_CATEGORY_II_REVIEW_REQUIRED = "CANDIDATE_CATEGORY_II_REVIEW_REQUIRED"


# Human-readable statutory label for a correlated telemetry-loss candidate
# (Category (ii) of CERT-In Annexure I). Emitted only as a *candidate* that a
# human must confirm — the watchdog never auto-confirms or files an incident.
CANDIDATE_CATEGORY_II_LABEL = "Category (ii) — Compromise of critical systems / information"


@dataclass(frozen=True, slots=True)
class TelemetryLossAssessment:
    """Full disposition of a telemetry-loss event.

    ``HeartbeatWatchdog.assess_telemetry_loss`` returns only the bare disposition
    enum. This richer result additionally carries the *proposed* statutory
    clock-start (``proposed_noticed_at_utc``) that a downstream 6-hour reporting
    clock needs, plus the statutory label and a human-readable reason.

    A ``CANDIDATE_CATEGORY_II_REVIEW_REQUIRED`` assessment is never a confirmed
    incident: ``requires_human_confirmation`` is ``True`` and
    ``proposed_noticed_at_utc`` is a *proposed* awareness timestamp pending a
    reviewer's sign-off, not an automatic filing trigger. An operational warning
    carries neither a proposed ``noticed_at`` nor a statutory category.
    """

    disposition: TelemetryLossDisposition
    loss_detected_at_utc: datetime
    reason: str
    requires_human_confirmation: bool
    proposed_noticed_at_utc: datetime | None = None
    statutory_category: str | None = None
    latest_high_confidence_intrusion_at_utc: datetime | None = None


@dataclass(frozen=True, slots=True)
class HeartbeatPayload:
    """Strict representation of ``heartbeat.schema.json``.

    ``agent_id`` is informational. A receiver must derive the trusted identity from
    the verified mTLS client certificate and may then compare it with this value.
    """

    FIELD_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "agent_id",
            "boot_id",
            "sequence",
            "sent_at_utc",
            "last_event_sequence",
            "last_event_hash",
            "agent_health",
            "signature",
        }
    )

    agent_id: str
    boot_id: UUID
    sequence: int
    sent_at_utc: datetime
    last_event_sequence: int
    last_event_hash: str
    agent_health: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not (1 <= len(self.agent_id) <= 128):
            raise HeartbeatValidationError("agent_id must contain 1 to 128 characters")
        if not isinstance(self.boot_id, UUID):
            raise HeartbeatValidationError("boot_id must be a UUID")
        self._validate_nonnegative_integer("sequence", self.sequence)
        self._validate_nonnegative_integer("last_event_sequence", self.last_event_sequence)
        if (
            not isinstance(self.sent_at_utc, datetime)
            or self.sent_at_utc.tzinfo is None
            or self.sent_at_utc.utcoffset() != timedelta(0)
        ):
            raise HeartbeatValidationError("sent_at_utc must be timezone-aware UTC")
        if not isinstance(self.last_event_hash, str) or not _SHA256_HEX.fullmatch(
            self.last_event_hash
        ):
            raise HeartbeatValidationError(
                "last_event_hash must be a lowercase 64-character SHA-256 hex digest"
            )
        if self.agent_health != "healthy":
            raise HeartbeatValidationError("agent_health must be 'healthy'")
        self._validate_signature(self.signature)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> HeartbeatPayload:
        """Parse a mapping while rejecting missing or unexpected fields."""

        actual_fields = frozenset(payload.keys())
        if actual_fields != cls.FIELD_NAMES:
            missing = sorted(cls.FIELD_NAMES - actual_fields)
            unexpected = sorted(actual_fields - cls.FIELD_NAMES)
            raise HeartbeatValidationError(
                f"payload fields differ from schema; missing={missing}, unexpected={unexpected}"
            )

        boot_id = payload["boot_id"]
        sent_at_utc = payload["sent_at_utc"]
        if not isinstance(boot_id, str):
            raise HeartbeatValidationError("boot_id must be a UUID string")
        if not isinstance(sent_at_utc, str) or not sent_at_utc.endswith("Z"):
            raise HeartbeatValidationError("sent_at_utc must be an ISO 8601 UTC string ending in Z")

        try:
            parsed_boot_id = UUID(boot_id)
        except ValueError as exc:
            raise HeartbeatValidationError("boot_id must be a valid UUID") from exc
        try:
            parsed_sent_at = datetime.fromisoformat(sent_at_utc[:-1] + "+00:00")
        except ValueError as exc:
            raise HeartbeatValidationError("sent_at_utc must be a valid ISO 8601 timestamp") from exc

        return cls(
            agent_id=payload["agent_id"],  # type: ignore[arg-type]
            boot_id=parsed_boot_id,
            sequence=payload["sequence"],  # type: ignore[arg-type]
            sent_at_utc=parsed_sent_at,
            last_event_sequence=payload["last_event_sequence"],  # type: ignore[arg-type]
            last_event_hash=payload["last_event_hash"],  # type: ignore[arg-type]
            agent_health=payload["agent_health"],  # type: ignore[arg-type]
            signature=payload["signature"],  # type: ignore[arg-type]
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "boot_id": str(self.boot_id),
            "sequence": self.sequence,
            "sent_at_utc": self.sent_at_utc.isoformat().replace("+00:00", "Z"),
            "last_event_sequence": self.last_event_sequence,
            "last_event_hash": self.last_event_hash,
            "agent_health": self.agent_health,
            "signature": self.signature,
        }

    def signing_bytes(self) -> bytes:
        """Return the documented canonical bytes covered by the Ed25519 signature.

        The preimage is compact UTF-8 JSON with lexicographically sorted keys and all
        payload fields except ``signature``. Go and Python producers can reproduce this
        without depending on a JSON-canonicalization package.
        """

        unsigned = self.to_mapping()
        del unsigned["signature"]
        return json.dumps(
            unsigned,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _validate_nonnegative_integer(name: str, value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HeartbeatValidationError(f"{name} must be a non-negative integer")

    @staticmethod
    def _validate_signature(signature: object) -> None:
        if not isinstance(signature, str):
            raise HeartbeatValidationError("signature must be a base64 string")
        try:
            raw_signature = base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HeartbeatValidationError("signature must be valid base64") from exc
        if len(raw_signature) != 64:
            raise HeartbeatValidationError("signature must decode to a 64-byte Ed25519 signature")


@dataclass(slots=True)
class HeartbeatGenerator:
    """Generate sequential signed payloads through an injected Ed25519 signer.

    The signer callback receives ``HeartbeatPayload.signing_bytes()`` and must return
    exactly 64 signature bytes. Key storage and cryptographic implementation remain the
    caller's responsibility, keeping this shared module dependency-free and network-free.
    """

    agent_id: str
    boot_id: UUID
    signer: Callable[[bytes], bytes]
    next_sequence: int = 0

    def __post_init__(self) -> None:
        if not callable(self.signer):
            raise ValueError("signer must be callable")
        HeartbeatPayload._validate_nonnegative_integer("next_sequence", self.next_sequence)

    def generate(
        self,
        *,
        sent_at_utc: datetime,
        last_event_sequence: int,
        last_event_hash: str,
    ) -> HeartbeatPayload:
        unsigned_payload = HeartbeatPayload(
            agent_id=self.agent_id,
            boot_id=self.boot_id,
            sequence=self.next_sequence,
            sent_at_utc=sent_at_utc,
            last_event_sequence=last_event_sequence,
            last_event_hash=last_event_hash,
            agent_health="healthy",
            signature=_PLACEHOLDER_SIGNATURE,
        )
        signature_bytes = self.signer(unsigned_payload.signing_bytes())
        if not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
            raise HeartbeatValidationError("signer must return a 64-byte Ed25519 signature")

        signed_payload = replace(
            unsigned_payload,
            signature=base64.b64encode(signature_bytes).decode("ascii"),
        )
        self.next_sequence += 1
        return signed_payload


@dataclass(slots=True)
class HeartbeatWatchdog:
    """Minimal heartbeat state machine driven by caller-supplied monotonic time.

    Call ``start`` when monitoring begins, then ``record_heartbeat`` for each accepted
    heartbeat and ``evaluate`` on a scheduler. With the demo defaults, the state changes
    at exactly 15 seconds without a heartbeat. This threshold is demo-tuned, not a claim
    about production compromise-detection latency.
    """

    heartbeat_interval_seconds: float = HEARTBEAT_INTERVAL_SECONDS
    missed_heartbeat_limit: int = MISSED_HEARTBEAT_LIMIT
    correlation_window_seconds: float = INTRUSION_CORRELATION_WINDOW_SECONDS
    _state: WatchdogState = field(default=WatchdogState.HEALTHY, init=False)
    _last_observed_monotonic: float | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._validate_positive_finite("heartbeat_interval_seconds", self.heartbeat_interval_seconds)
        if (
            isinstance(self.missed_heartbeat_limit, bool)
            or not isinstance(self.missed_heartbeat_limit, int)
            or self.missed_heartbeat_limit <= 0
        ):
            raise ValueError("missed_heartbeat_limit must be a positive integer")
        self._validate_positive_finite("correlation_window_seconds", self.correlation_window_seconds)

    @property
    def state(self) -> WatchdogState:
        return self._state

    @property
    def telemetry_loss_after_seconds(self) -> float:
        return self.heartbeat_interval_seconds * self.missed_heartbeat_limit

    def start(self, now_monotonic: float) -> None:
        """Begin monitoring from a validated monotonic-clock reading."""

        self._validate_clock(now_monotonic)
        if self._last_observed_monotonic is not None:
            raise RuntimeError("watchdog monitoring has already started")
        self._last_observed_monotonic = now_monotonic
        self._state = WatchdogState.HEALTHY

    def record_heartbeat(self, received_monotonic: float) -> WatchdogState:
        """Record an accepted heartbeat and restore telemetry health."""

        self._validate_clock(received_monotonic)
        self._validate_not_before_last_observation(received_monotonic)
        self._last_observed_monotonic = received_monotonic
        self._state = WatchdogState.HEALTHY
        return self._state

    def missed_heartbeats(self, now_monotonic: float) -> int:
        """Return the number of complete expected intervals since the last observation."""

        elapsed = self._elapsed(now_monotonic)
        return math.floor(elapsed / self.heartbeat_interval_seconds)

    def evaluate(self, now_monotonic: float) -> WatchdogState:
        """Transition to telemetry loss after the configured missed-heartbeat limit."""

        if self.missed_heartbeats(now_monotonic) >= self.missed_heartbeat_limit:
            self._state = WatchdogState.TELEMETRY_LOSS
        return self._state

    def assess_telemetry_loss(
        self,
        *,
        loss_detected_at_utc: datetime,
        latest_high_confidence_intrusion_at_utc: datetime | None,
    ) -> TelemetryLossDisposition:
        """Classify telemetry loss without confirming or creating an incident.

        Correlated evidence only returns a candidate Category (ii) disposition that a
        human must review. No evidence (or stale evidence) remains an operational warning.
        """

        if self._state is not WatchdogState.TELEMETRY_LOSS:
            raise RuntimeError("telemetry loss can only be assessed in TELEMETRY_LOSS state")
        self._validate_utc("loss_detected_at_utc", loss_detected_at_utc)
        if latest_high_confidence_intrusion_at_utc is None:
            return TelemetryLossDisposition.OPERATIONAL_WARNING
        self._validate_utc(
            "latest_high_confidence_intrusion_at_utc",
            latest_high_confidence_intrusion_at_utc,
        )
        age_seconds = (
            loss_detected_at_utc - latest_high_confidence_intrusion_at_utc
        ).total_seconds()
        if 0 <= age_seconds <= self.correlation_window_seconds:
            return TelemetryLossDisposition.CANDIDATE_CATEGORY_II_REVIEW_REQUIRED
        return TelemetryLossDisposition.OPERATIONAL_WARNING

    def assess_telemetry_loss_detailed(
        self,
        *,
        loss_detected_at_utc: datetime,
        latest_high_confidence_intrusion_at_utc: datetime | None,
    ) -> TelemetryLossAssessment:
        """Classify telemetry loss and build the full escalation packet.

        Wraps :meth:`assess_telemetry_loss` (which owns the state check and the
        correlation-window logic) and adds the fields a statutory reporting
        workflow consumes. A candidate Category (ii) result carries a *proposed*
        ``noticed_at`` and always requires human confirmation; an operational
        warning carries neither. This method still never confirms or files an
        incident — it only describes the disposition.
        """

        disposition = self.assess_telemetry_loss(
            loss_detected_at_utc=loss_detected_at_utc,
            latest_high_confidence_intrusion_at_utc=latest_high_confidence_intrusion_at_utc,
        )
        if disposition is TelemetryLossDisposition.CANDIDATE_CATEGORY_II_REVIEW_REQUIRED:
            return TelemetryLossAssessment(
                disposition=disposition,
                loss_detected_at_utc=loss_detected_at_utc,
                reason=(
                    "Host telemetry flatlined within "
                    f"{self.correlation_window_seconds:g}s of high-confidence intrusion "
                    "activity. Candidate Category (ii); requires human confirmation."
                ),
                requires_human_confirmation=True,
                proposed_noticed_at_utc=loss_detected_at_utc,
                statutory_category=CANDIDATE_CATEGORY_II_LABEL,
                latest_high_confidence_intrusion_at_utc=latest_high_confidence_intrusion_at_utc,
            )
        return TelemetryLossAssessment(
            disposition=disposition,
            loss_detected_at_utc=loss_detected_at_utc,
            reason="Telemetry drop without correlated intrusion evidence. Operational warning.",
            requires_human_confirmation=False,
        )

    def _elapsed(self, now_monotonic: float) -> float:
        self._validate_clock(now_monotonic)
        if self._last_observed_monotonic is None:
            raise RuntimeError("call start() or record_heartbeat() before evaluating the watchdog")
        self._validate_not_before_last_observation(now_monotonic)
        return now_monotonic - self._last_observed_monotonic

    def _validate_not_before_last_observation(self, now_monotonic: float) -> None:
        if (
            self._last_observed_monotonic is not None
            and now_monotonic < self._last_observed_monotonic
        ):
            raise ValueError("monotonic clock value cannot move backwards")

    @staticmethod
    def _validate_clock(value: float) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("monotonic clock value must be finite")

    @staticmethod
    def _validate_positive_finite(name: str, value: float) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{name} must be finite")
        if value <= 0:
            raise ValueError(f"{name} must be positive")

    @staticmethod
    def _validate_utc(name: str, value: datetime) -> None:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be timezone-aware UTC")
