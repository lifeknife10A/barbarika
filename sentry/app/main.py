"""FastAPI app: mTLS ingest -> hash-chained SQLite -> rule eval -> SSE/incidents.

Vertical slice for the Sentry backend milestone:
  POST /ingest          mTLS-gated; seals + chains the event, evaluates rules,
                        records incidents, broadcasts to live subscribers.
  GET  /events          recent events, masked by default.
  GET  /events/{id}     one event; ?unmask=true is an authenticated, audited action.
  GET  /events/stream   Server-Sent Events (replay recent, then live).
  GET  /incidents       incidents recorded by the detector.
  GET  /health          status, journal_mode, counts, loaded rule count.

Still honest about scope: Ed25519 signature verification is agent-side and is
NOT asserted here; this chain proves contiguity + tamper-evidence only.
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

from . import crypto, db, mtls
from .broadcast import Broadcaster
from .detect import Detector, load_rules
from .models import EventAck, EventIn, EventOut, IncidentOut

logger = logging.getLogger("sentry")


class State:
    key: bytes
    detector: Detector
    broadcaster: Broadcaster


state = State()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    state.key = crypto.load_or_create_key()
    state.detector = Detector(load_rules())
    state.broadcaster = Broadcaster()
    state.broadcaster.bind_loop(asyncio.get_running_loop())
    logger.info("sentry ready: %d detection rule(s) loaded", state.detector.rule_count)
    yield


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


@app.post("/ingest", response_model=EventAck, status_code=200)
def ingest(
    event: EventIn,
    agent_identity: str = Depends(mtls.require_client_identity),
) -> EventAck:
    try:
        event.validate_category()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    received_at = datetime.now(timezone.utc)
    conn = db.connect()
    try:
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
