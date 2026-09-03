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
    # Identity the signing key was bound to (mTLS CN or agent_id); see
    # services/identity.py.
    signer_identity = Column(String, nullable=True, index=True)


class AgentKey(Base):
    """Pinned public key for an agent identity (trust-on-first-use).

    The first verified public key seen for an identity is pinned here; later
    events for that identity must present the same key or they are rejected.
    """

    __tablename__ = "agent_keys"

    identity = Column(String, primary_key=True)  # mTLS CN (authoritative) or agent_id
    pubkey = Column(String, nullable=False)       # base64 Ed25519 public key
    first_seen = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)


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
