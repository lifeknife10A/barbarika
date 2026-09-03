import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..services import hash_chain, signatures, identity
from ..database import SessionLocal, engine, Base

router = APIRouter()

# Ensure tables are created
Base.metadata.create_all(bind=engine)

# Reject events that arrive without a signature when strict mode is on.
REQUIRE_SIGNATURE = os.getenv("SENTRY_REQUIRE_SIGNATURE") == "1"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def raw_json(request: Request) -> dict:
    """The exact request body as a dict.

    Ed25519 verification must run over the bytes the agent signed (notably the
    wire timestamp string), which the parsed EventIn model would not reproduce.
    FastAPI caches the body, so this and the EventIn parameter read the same one.
    """
    return await request.json()

@router.post(
    "/events",
    response_model=schemas.EventOut,
    status_code=status.HTTP_201_CREATED,
    tags=["events"]
)
def ingest_event(
    event: schemas.EventIn,
    request: Request,
    raw: dict = Depends(raw_json),
    db: Session = Depends(get_db),
):
    # Receive-side Ed25519 verification over the exact signed bytes. A present-
    # but-invalid signature means the event was altered in transit -> reject it.
    verified, sig_status, signer_pubkey = signatures.verify_event_signature(raw)
    if sig_status == signatures.INVALID:
        raise HTTPException(status_code=400, detail="invalid event signature")
    if sig_status == signatures.UNSIGNED and REQUIRE_SIGNATURE:
        raise HTTPException(status_code=401, detail="event signature required")

    # Key-to-identity binding: a verified key is pinned to its identity (mTLS CN
    # when forwarded, else agent_id). A different key for a pinned identity is an
    # impersonation attempt -> reject.
    signer_identity = None
    if verified:
        signer_identity = identity.resolve_identity(
            request.headers.get(identity.cn_header_name()), event.agent_id
        )
        ok, _bind_status = identity.bind_key(db, signer_identity, signer_pubkey)
        if not ok:
            raise HTTPException(
                status_code=409,
                detail=f"signing key does not match the key pinned for '{signer_identity}'",
            )

    # Find the most recent event for this agent to get its hash
    prior = (
        db.query(models.Event)
        .filter(models.Event.agent_id == event.agent_id)
        .order_by(models.Event.sequence.desc())
        .first()
    )
    prev_hash = prior.cur_hash if prior else ""

    # Canonical UTC, tz-naive timestamp so the hash matches after the value is
    # read back from SQLite at verify time (SQLite drops tzinfo). Store the same
    # canonical value we hash, so ingest and verification always agree.
    ts_iso = hash_chain.to_utc_naive_iso(event.timestamp)
    ts_stored = datetime.fromisoformat(ts_iso)

    # Build the dictionary that will be hashed (exclude hash fields)
    event_dict = {
        "agent_id": event.agent_id,
        "sequence": event.sequence,
        "timestamp": ts_iso,
        "source": event.source,
        "event_type": event.event_type,
        "payload": event.payload,
    }

    cur_hash = hash_chain.compute_hash(prev_hash, ts_iso, event_dict)

    db_event = models.Event(
        agent_id=event.agent_id,
        sequence=event.sequence,
        timestamp=ts_stored,
        source=event.source,
        event_type=event.event_type,
        payload=event.payload,
        prev_hash=prev_hash or None,
        cur_hash=cur_hash,
        signature_verified=verified,
        signer_pubkey=signer_pubkey,
        signer_identity=signer_identity,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # NOTE: SQLite (WAL) is the single authoritative evidence store. The event's
    # integrity is guaranteed by the append-only hash chain above; there is no
    # second NDJSON copy to drift out of sync (see integration/CONTRACT.md).

    return schemas.EventOut(
        id=db_event.id,
        agent_id=db_event.agent_id,
        sequence=db_event.sequence,
        timestamp=db_event.timestamp,
        source=db_event.source,
        event_type=db_event.event_type,
        payload=db_event.payload,
        prev_hash=db_event.prev_hash,
        cur_hash=db_event.cur_hash,
        signature_verified=db_event.signature_verified,
        signer_pubkey=db_event.signer_pubkey,
        signer_identity=db_event.signer_identity,
    )

# Optional: GET endpoint to retrieve events (for testing/frontend)
@router.get("/events", response_model=list[schemas.EventOut], tags=["events"])
def list_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(models.Event).order_by(models.Event.id).offset(skip).limit(limit).all()
    return events

@router.get("/events/{event_id}", response_model=schemas.EventOut, tags=["events"])
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
