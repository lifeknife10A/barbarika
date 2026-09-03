from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from .. import models, schemas
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
    "/heartbeat",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["heartbeat"]
)
def receive_heartbeat(hb: schemas.HeartbeatIn, db: Session = Depends(get_db)):
    db_hb = models.Heartbeat(**hb.dict())
    db.add(db_hb)
    db.commit()
    return {"detail": "heartbeat recorded"}
