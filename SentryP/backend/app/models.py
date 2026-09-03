import datetime
from sqlalchemy import Boolean, Column, Integer, String, DateTime, JSON, Text
from .database import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, nullable=False, index=True)
    sequence = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    prev_hash = Column(String, nullable=True)
    cur_hash = Column(String, nullable=False, index=True)
    # Receive-side Ed25519 verification result (see services/signatures.py).
    signature_verified = Column(Boolean, nullable=False, default=False)
    signer_pubkey = Column(String, nullable=True)


class Heartbeat(Base):
    __tablename__ = "heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, nullable=False, index=True)
    boot_id = Column(String, nullable=False)
    sequence = Column(Integer, nullable=False)
    sent_at_utc = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    last_event_sequence = Column(Integer, nullable=True)
    last_event_hash = Column(String, nullable=True)
    agent_health = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
