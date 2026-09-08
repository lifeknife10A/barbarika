"""FastAPI app: mTLS ingest -> hash-chained SQLite -> rule eval -> SSE/incidents.

Vertical slice for the Sentry backend milestone:
  POST /ingest          mTLS-gated; seals + chains the event, evaluates rules,
                        records incidents, broadcasts to live subscribers.
  GET  /events          recent events, masked by default.
  GET  /events/{id}     one event; ?unmask=true is an authenticated, audited action.
  GET  /events/stream   Server-Sent Events (replay recent, then live).
  GET  /incidents       incidents recorded by the detector.
  POST /heartbeat       signed 5s liveness ping; drives the dead-man's-switch watchdog.
  GET  /watchdog        per-agent liveness (HEALTHY / TELEMETRY_LOSS + candidate cat).
  GET  /health          status, journal_mode, counts, loaded rule count.

Ed25519 signatures are verified receive-side on both /ingest (per event) and
/heartbeat (per ping); the hash chain additionally proves contiguity + tamper-
evidence for stored events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from . import crypto, db, mtls, signatures, watchdog
from .broadcast import Broadcaster
from .detect import Detector, load_rules
from .models import (
    EventAck,
    EventIn,
    EventOut,
    HeartbeatAck,
    HostOut,
    HostSnapshot,
    IncidentOut,
    WatchdogStatusOut,
)

logger = logging.getLogger("sentry")

# Reject events that arrive without a signature when strict mode is on.
REQUIRE_SIGNATURE = os.environ.get("SENTRY_REQUIRE_SIGNATURE") == "1"


async def _raw_json(request: Request) -> dict:
    """The exact request body as a dict.

    Ed25519 verification must run over the bytes the agent signed (notably the
    wire occurred_at string), which the parsed EventIn would not reproduce.
    FastAPI caches the body, so this and the EventIn parameter read the same one.
    """
    return await request.json()


class State:
    key: bytes
    detector: Detector
    broadcaster: Broadcaster
    # Latest operational snapshot per agent host (volatile, not chained).
    latest_host: dict[str, dict]
    # Dead-man's-switch: per-agent heartbeat liveness.
    watchdog: watchdog.WatchdogManager
    watchdog_task: asyncio.Task | None


state = State()

# How often the background evaluator re-checks liveness and broadcasts flips.
WATCHDOG_EVAL_INTERVAL_SECONDS = 1.0


def _latest_intrusion_utc(conn: sqlite3.Connection) -> datetime | None:
    """Wall-clock time of the most recent recorded incident, for the 120s
    telemetry-loss correlation. Returns None if no incident has fired."""
    rows = db.list_incidents(conn, limit=1)
    if not rows:
        return None
    stamp = rows[0]["detected_at"] or rows[0]["created_at"]
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _watchdog_loop() -> None:
    """Periodically evaluate agent liveness; broadcast every state transition so a
    dead-man's-switch flip reaches the dashboard live."""
    while True:
        try:
            await asyncio.sleep(WATCHDOG_EVAL_INTERVAL_SECONDS)
            conn = db.connect()
            try:
                latest = _latest_intrusion_utc(conn)
            finally:
                conn.close()
            for st in state.watchdog.poll_transitions(latest_intrusion_utc=latest):
                if st["state"] == watchdog.WatchdogState.TELEMETRY_LOSS.value:
                    logger.warning(
                        "WATCHDOG telemetry loss agent=%s disposition=%s",
                        st.get("agent_id"), st.get("disposition"),
                    )
                state.broadcaster.publish(
                    {"type": "watchdog", "data": WatchdogStatusOut(**st).model_dump(mode="json")}
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # never let the evaluator die on a transient error
            logger.exception("watchdog evaluator iteration failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    state.key = crypto.load_or_create_key()
    state.detector = Detector(load_rules())
    state.broadcaster = Broadcaster()
    state.broadcaster.bind_loop(asyncio.get_running_loop())
    state.latest_host = {}
    state.watchdog = watchdog.WatchdogManager()
    state.watchdog_task = asyncio.create_task(_watchdog_loop())
    logger.info("sentry ready: %d detection rule(s) loaded", state.detector.rule_count)
    try:
        yield
    finally:
        state.watchdog_task.cancel()
        try:
            await state.watchdog_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Barbarika Sentry",
    version="0.2.0",
    summary="mTLS ingestion API, hash-chained SQLite vault, live event/incident stream.",
    lifespan=lifespan,
)


def _row_to_event_out(row: sqlite3.Row, *, unmask: bool) -> EventOut:
    raw_message, payload = crypto.unseal_content(state.key, row["sealed_blob"])
    if not unmask:
        raw_message = crypto.mask_text(raw_message)
        payload = crypto.mask_payload(payload)
    return EventOut(
        id=row["id"],
        seq=row["seq"],
        event_type=row["event_type"],
        source=row["source"],
        severity=row["severity"],
        category=row["category"],
        occurred_at=row["occurred_at"],
        detected_at=row["detected_at"],
        received_at=row["received_at"],
        raw_message=raw_message,
        payload=payload,
        row_hash=row["row_hash"],
        masked=not unmask,
        signature_verified=bool(row["signature_verified"]),
        signer_identity=row["signer_identity"],
        signer_pubkey=row["signer_pubkey"],
    )


def _row_to_incident_out(row: sqlite3.Row) -> IncidentOut:
    return IncidentOut(
        id=row["id"],
        incident_uuid=row["incident_uuid"],
        rule_id=row["rule_id"],
        rule_title=row["rule_title"],
        category=row["category"],
        event_ids=json.loads(row["event_ids_json"]),
        detected_at=row["detected_at"],
        created_at=row["created_at"],
    )


@app.get("/health")
def health() -> dict[str, object]:
    conn = db.connect()
    try:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        return {
            "status": "ok",
            "journal_mode": journal_mode,
            "events": db.count_events(conn),
            "incidents": len(db.list_incidents(conn, limit=1_000_000)),
            "rules_loaded": state.detector.rule_count,
            "mtls": "dev-insecure" if os.environ.get("SENTRY_DEV_INSECURE") == "1" else "required",
        }
    finally:
        conn.close()


@app.post("/host", status_code=204)
def report_host(
    snap: HostSnapshot,
    agent_identity: str = Depends(mtls.require_client_identity),
) -> None:
    """Record an agent host's latest operational snapshot (overwrites prior).

    Not sealed, not hash-chained — this is volatile status, not evidence. Keyed
    by the mTLS-resolved identity so one agent cannot overwrite another's row.
    """
    stored = snap.model_dump()
    stored["received_at"] = datetime.now(timezone.utc).isoformat()
    state.latest_host[agent_identity] = stored


@app.get("/host", response_model=list[HostOut])
def list_host(_: str = Depends(mtls.require_client_identity)) -> list[HostOut]:
    """The latest operational snapshot for each known agent host."""
    return [HostOut(**snap) for snap in state.latest_host.values()]


@app.post("/heartbeat", response_model=HeartbeatAck, status_code=202)
async def heartbeat(
    request: Request,
    x_public_key: str | None = Header(default=None),
    agent_identity: str = Depends(mtls.require_client_identity),
) -> HeartbeatAck:
    """Receive a signed agent heartbeat and refresh the dead-man's-switch watchdog.

    Validates the payload against the shared heartbeat schema and verifies its
    Ed25519 signature over the canonical preimage (public key in ``X-Public-Key``).
    Liveness is keyed by the mTLS-resolved identity, so one agent cannot reset
    another's timer. A missing/invalid signature is handled like ``/ingest``:
    rejected outright when invalid, and required only in strict mode.
    """
    body = await request.json()
    try:
        payload = watchdog.HeartbeatPayload.from_mapping(body)
    except watchdog.HeartbeatValidationError as exc:
        raise HTTPException(status_code=422, detail=f"invalid heartbeat: {exc}") from exc

    verified, sig_status = watchdog.verify_heartbeat_signature(payload, x_public_key)
    if sig_status == watchdog.INVALID:
        raise HTTPException(status_code=400, detail="invalid heartbeat signature")
    if sig_status == watchdog.UNSIGNED and REQUIRE_SIGNATURE:
        raise HTTPException(status_code=401, detail="heartbeat signature required")

    live = state.watchdog.record(agent_identity, payload, signature_verified=verified)
    return HeartbeatAck(
        agent_id=payload.agent_id,
        sequence=payload.sequence,
        signature_verified=verified,
        state=live.watchdog.state.value,
    )


@app.get("/watchdog", response_model=list[WatchdogStatusOut])
def watchdog_status(_: str = Depends(mtls.require_client_identity)) -> list[WatchdogStatusOut]:
    """Current liveness for every agent that has ever sent a heartbeat.

    Evaluated live: an agent silent past the 3-missed-beats (15s) threshold reads
    as ``TELEMETRY_LOSS``, and if an incident fired within the last 120s it carries
    a *candidate* Category (ii) disposition awaiting human confirmation.
    """
    conn = db.connect()
    try:
        latest = _latest_intrusion_utc(conn)
    finally:
        conn.close()
    return [WatchdogStatusOut(**st) for st in state.watchdog.snapshot(latest_intrusion_utc=latest)]


@app.post("/ingest", response_model=EventAck, status_code=200)
def ingest(
    event: EventIn,
    raw: dict = Depends(_raw_json),
    agent_identity: str = Depends(mtls.require_client_identity),
) -> EventAck:
    try:
        event.validate_category()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Receive-side Ed25519 verification over the exact signed bytes. A present-
    # but-invalid signature means the event was altered in transit -> reject it.
    verified, sig_status, signer_pubkey = signatures.verify_event_signature(raw)
    if sig_status == signatures.INVALID:
        raise HTTPException(status_code=400, detail="invalid event signature")
    if sig_status == signatures.UNSIGNED and REQUIRE_SIGNATURE:
        raise HTTPException(status_code=401, detail="event signature required")

    received_at = datetime.now(timezone.utc)
    conn = db.connect()
    try:
        # Key-to-identity binding: a verified key is pinned to its identity (the
        # mTLS-resolved identity). A different key for a pinned identity is an
        # impersonation attempt -> reject.
        signer_identity = None
        if verified:
            signer_identity = agent_identity
            ok, _bind_status = db.bind_key(conn, signer_identity, signer_pubkey)
            if not ok:
                raise HTTPException(
                    status_code=409,
                    detail=f"signing key does not match the key pinned for '{signer_identity}'",
                )

        result = db.append_event(
            conn,
            state.key,
            event_type=event.event_type,
            source=event.source,
            severity=event.severity,
            category=event.category,
            occurred_at=event.occurred_at,
            detected_at=event.detected_at,
            received_at=received_at,
            raw_message=event.raw_message,
            payload=event.payload,
            signature_verified=verified,
            signer_identity=signer_identity,
            signer_pubkey=signer_pubkey,
        )

        # Broadcast the event (masked) to live subscribers.
        state.broadcaster.publish(
            {
                "type": "event",
                "data": _row_to_event_out(
                    db.get_event(conn, result["id"]), unmask=False
                ).model_dump(mode="json"),
            }
        )

        # Run detection; persist + broadcast any new incident.
        incidents = state.detector.observe(
            sentry_event_id=result["id"],
            source=event.source,
            raw_message=event.raw_message,
            category=event.category,
            occurred_at=event.occurred_at,
            detected_at=event.detected_at,
            received_at=received_at,
        )
        for inc in incidents:
            created_at = datetime.now(timezone.utc).isoformat()
            stored = db.record_incident(
                conn,
                incident_uuid=inc["incident_uuid"],
                rule_id=inc["rule_id"],
                rule_title=inc["rule_title"],
                category=inc["category"],
                event_ids_json=json.dumps(inc["event_ids"]),
                detected_at=inc["detected_at"],
                created_at=created_at,
                signature=inc["signature"],
            )
            if stored:
                logger.warning(
                    "INCIDENT category=%s rule=%s events=%s (agent=%s)",
                    inc["category"], inc["rule_title"], inc["event_ids"], agent_identity,
                )
                state.broadcaster.publish(
                    {"type": "incident", "data": {**inc, "created_at": created_at}}
                )
    finally:
        conn.close()

    return EventAck(
        id=result["id"], seq=result["seq"],
        received_at=result["received_at"], row_hash=result["row_hash"],
    )


@app.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(mtls.require_client_identity),
) -> list[EventOut]:
    conn = db.connect()
    try:
        return [_row_to_event_out(r, unmask=False) for r in db.recent_events(conn, limit)]
    finally:
        conn.close()


def _sse(message: dict) -> str:
    return f"event: {message['type']}\ndata: {json.dumps(message['data'])}\n\n"


@app.get("/events/stream")
async def events_stream(
    request: Request,
    replay: int = Query(default=50, ge=0, le=500),
    once: bool = Query(default=False, description="Emit replay then close (finite, for tools/tests)."),
    _: str = Depends(mtls.require_client_identity),
) -> StreamingResponse:
    """SSE: replay recent events, then (unless once=true) stream live events + incidents."""
    queue = state.broadcaster.subscribe()

    async def gen():
        try:
            yield ": connected\n\n"
            conn = db.connect()
            try:
                for row in db.recent_events(conn, replay):
                    yield _sse(
                        {"type": "event", "data": _row_to_event_out(row, unmask=False).model_dump(mode="json")}
                    )
            finally:
                conn.close()
            if once:
                return
            # Live tail. Short poll interval so client disconnects are noticed promptly;
            # emit an SSE keepalive comment roughly every 15s (demo keepalive, not a health claim).
            idle = 0.0
            while not await request.is_disconnected():
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield _sse(message)
                    idle = 0.0
                except asyncio.TimeoutError:
                    idle += 1.0
                    if idle >= 15.0:
                        idle = 0.0
                        yield ": keepalive\n\n"
        finally:
            state.broadcaster.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/events/{event_id}", response_model=EventOut)
def get_event(
    event_id: int,
    unmask: bool = Query(default=False),
    x_unmask_token: str | None = Header(default=None),
    _: str = Depends(mtls.require_client_identity),
) -> EventOut:
    if unmask:
        expected = os.environ.get("SENTRY_UNMASK_TOKEN")
        if not expected or x_unmask_token != expected:
            raise HTTPException(status_code=403, detail="unmask requires a valid audit token")
        logger.warning("AUDIT unmask event_id=%s", event_id)  # audited action
    conn = db.connect()
    try:
        row = db.get_event(conn, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="event not found")
        return _row_to_event_out(row, unmask=unmask)
    finally:
        conn.close()


@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    limit: int = Query(default=100, ge=1, le=1000),
    _: str = Depends(mtls.require_client_identity),
) -> list[IncidentOut]:
    conn = db.connect()
    try:
        return [_row_to_incident_out(r) for r in db.list_incidents(conn, limit)]
    finally:
        conn.close()
