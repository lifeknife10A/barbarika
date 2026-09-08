"""Live dead-man's-switch: receive signed heartbeats and run the transport watchdog.

This is the receive-side of the heartbeat protocol. The agent already emits a
signed heartbeat every 5s (``POST /heartbeat``); this module validates it, verifies
its Ed25519 signature, and tracks per-agent liveness with Jash's
``transport/heartbeat.py`` state machine (stdlib-only, network-free).

Semantics (unchanged from ``transport/heartbeat.py``): after 3 missed 5s beats
(15s) an agent flips to ``TELEMETRY_LOSS``. That alone is only an operational
warning; but if a high-confidence incident fired within the last 120s, the loss is
surfaced as a *candidate* Category (ii) that a human must confirm — the watchdog
never auto-files an incident.
"""

from __future__ import annotations

import base64
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Reuse the shared transport module. Mirror the repo's existing cross-component
# import pattern (compliance/ imports sentry/ the same way): the monorepo always
# ships transport/ next to sentry/.
_TRANSPORT = Path(__file__).resolve().parents[2] / "transport"
if str(_TRANSPORT) not in sys.path:
    sys.path.insert(0, str(_TRANSPORT))

from heartbeat import (  # noqa: E402  (path injected above)
    HeartbeatPayload,
    HeartbeatValidationError,
    HeartbeatWatchdog,
    TelemetryLossDisposition,
    WatchdogState,
)

__all__ = [
    "HeartbeatPayload",
    "HeartbeatValidationError",
    "WatchdogManager",
    "verify_heartbeat_signature",
    "VERIFIED",
    "UNSIGNED",
    "INVALID",
]

VERIFIED = "verified"
UNSIGNED = "unsigned"
INVALID = "invalid"

# Correlate a telemetry blackout with intrusion evidence from the last 120s.
CORRELATION_WINDOW_SECONDS = 120.0


def verify_heartbeat_signature(
    payload: HeartbeatPayload, pubkey_b64: str | None
) -> tuple[bool, str]:
    """Verify the heartbeat's Ed25519 signature over the canonical preimage.

    The agent signs ``HeartbeatPayload.signing_bytes()`` (compact JSON, sorted
    keys, signature field excluded) with base64 std encoding, and sends the public
    key in the ``X-Public-Key`` header. Returns (verified, status) where status is
    ``verified`` / ``unsigned`` / ``invalid``.
    """
    if not pubkey_b64:
        return False, UNSIGNED
    try:
        pub_bytes = base64.b64decode(pubkey_b64)
        sig_bytes = base64.b64decode(payload.signature)
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
            sig_bytes, payload.signing_bytes()
        )
    except (InvalidSignature, ValueError, TypeError):
        return False, INVALID
    return True, VERIFIED


@dataclass
class AgentLiveness:
    """Per-agent liveness: the real state machine plus reporting metadata."""

    watchdog: HeartbeatWatchdog
    agent_id: str
    last_sequence: int
    last_seen_utc: datetime
    signature_verified: bool
    # State the background evaluator last *broadcast*; used to detect transitions
    # without racing GET /watchdog (which reads state but never broadcasts).
    reported_state: WatchdogState = WatchdogState.HEALTHY


@dataclass
class WatchdogManager:
    """Tracks liveness for every agent that has ever sent a heartbeat.

    Time is injectable (``now_monotonic`` / ``now_utc``) so the state machine can be
    driven deterministically in tests; production passes the real clocks.
    """

    correlation_window_seconds: float = CORRELATION_WINDOW_SECONDS
    _agents: dict[str, AgentLiveness] = field(default_factory=dict)

    # -- receive side ------------------------------------------------------
    def record(
        self,
        identity: str,
        payload: HeartbeatPayload,
        *,
        signature_verified: bool,
        now_monotonic: float | None = None,
        now_utc: datetime | None = None,
    ) -> AgentLiveness:
        """Record an accepted heartbeat, restoring the agent to HEALTHY."""
        now_monotonic = time.monotonic() if now_monotonic is None else now_monotonic
        now_utc = datetime.now(timezone.utc) if now_utc is None else now_utc

        live = self._agents.get(identity)
        if live is None:
            wd = HeartbeatWatchdog()
            wd.start(now_monotonic)
            live = AgentLiveness(
                watchdog=wd,
                agent_id=payload.agent_id,
                last_sequence=payload.sequence,
                last_seen_utc=now_utc,
                signature_verified=signature_verified,
            )
            self._agents[identity] = live
        else:
            # Ignore an out-of-order beat whose clock predates the last observation
            # rather than letting the state machine raise.
            try:
                live.watchdog.record_heartbeat(now_monotonic)
            except ValueError:
                return live

        live.agent_id = payload.agent_id
        live.last_sequence = payload.sequence
        live.last_seen_utc = now_utc
        live.signature_verified = signature_verified
        return live

    # -- read side ---------------------------------------------------------
    def status(
        self,
        identity: str,
        live: AgentLiveness,
        *,
        now_monotonic: float | None = None,
        now_utc: datetime | None = None,
        latest_intrusion_utc: datetime | None = None,
    ) -> dict:
        """Evaluate one agent and build its status dict (does not broadcast)."""
        now_monotonic = time.monotonic() if now_monotonic is None else now_monotonic
        now_utc = datetime.now(timezone.utc) if now_utc is None else now_utc

        st = live.watchdog.evaluate(now_monotonic)
        out: dict = {
            "identity": identity,
            "agent_id": live.agent_id,
            "state": st.value,
            "missed_heartbeats": live.watchdog.missed_heartbeats(now_monotonic),
            "last_sequence": live.last_sequence,
            "last_seen_utc": live.last_seen_utc,
            "signature_verified": live.signature_verified,
            "requires_human_confirmation": False,
        }
        if st is WatchdogState.TELEMETRY_LOSS:
            assessment = live.watchdog.assess_telemetry_loss_detailed(
                loss_detected_at_utc=now_utc,
                latest_high_confidence_intrusion_at_utc=latest_intrusion_utc,
            )
            out["disposition"] = assessment.disposition.value
            out["reason"] = assessment.reason
            out["requires_human_confirmation"] = assessment.requires_human_confirmation
            out["statutory_category"] = assessment.statutory_category
            out["proposed_noticed_at_utc"] = assessment.proposed_noticed_at_utc
        return out

    def snapshot(
        self,
        *,
        now_monotonic: float | None = None,
        now_utc: datetime | None = None,
        latest_intrusion_utc: datetime | None = None,
    ) -> list[dict]:
        """Read-only status for every known agent (no transition side effects)."""
        now_monotonic = time.monotonic() if now_monotonic is None else now_monotonic
        now_utc = datetime.now(timezone.utc) if now_utc is None else now_utc
        return [
            self.status(
                identity, live,
                now_monotonic=now_monotonic, now_utc=now_utc,
                latest_intrusion_utc=latest_intrusion_utc,
            )
            for identity, live in self._agents.items()
        ]

    def poll_transitions(
        self,
        *,
        now_monotonic: float | None = None,
        now_utc: datetime | None = None,
        latest_intrusion_utc: datetime | None = None,
    ) -> list[dict]:
        """Evaluate all agents and return the status of any that CHANGED state.

        The background evaluator calls this and broadcasts each returned status.
        ``reported_state`` is advanced here so a given transition is emitted once.
        """
        now_monotonic = time.monotonic() if now_monotonic is None else now_monotonic
        now_utc = datetime.now(timezone.utc) if now_utc is None else now_utc
        changed: list[dict] = []
        for identity, live in self._agents.items():
            out = self.status(
                identity, live,
                now_monotonic=now_monotonic, now_utc=now_utc,
                latest_intrusion_utc=latest_intrusion_utc,
            )
            new_state = live.watchdog.state
            if new_state is not live.reported_state:
                live.reported_state = new_state
                changed.append(out)
        return changed
