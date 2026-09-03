from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pathlib import Path

from .. import models, schemas
from ..services import hash_chain
from ..database import SessionLocal, engine, Base

router = APIRouter()

# Ensure tables are created
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post(
    "/events",
    response_model=schemas.EventOut,
    status_code=status.HTTP_201_CREATED,
    tags=["events"]
)
def ingest_event(event: schemas.EventIn, db: Session = Depends(get_db)):
    # Find the most recent event for this agent to get its hash
    prior = (
        db.query(models.Event)
        .filter(models.Event.agent_id == event.agent_id)
        .order_by(models.Event.sequence.desc())
        .first()
    )
    prev_hash = prior.cur_hash if prior else ""

    # Build the dictionary that will be hashed (exclude hash fields)
    event_dict = {
        "agent_id": event.agent_id,
        "sequence": event.sequence,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "payload": event.payload,
    }

    cur_hash = hash_chain.compute_hash(prev_hash, event.timestamp.isoformat(), event_dict)

    db_event = models.Event(
        agent_id=event.agent_id,
        sequence=event.sequence,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        payload=event.payload,
        prev_hash=prev_hash or None,
        cur_hash=cur_hash,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Append the raw JSON line to the daily NDJSON file (append-only)
    evidence_dir = Path(__file__).resolve().parents[2] / "data" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = evidence_dir / f"{datetime.utcnow().date()}.ndjson"
    with ndjson_path.open("a", encoding="utf-8") as f:
        f.write(event.json())
        f.write("\n")

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
