from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class EventIn(BaseModel):
    agent_id: str = Field(..., description="Identifier of the primary server/agent.")
    sequence: int = Field(..., description="Monotonically increasing sequence number per agent.")
    timestamp: datetime = Field(..., description="Event timestamp in UTC.")
    source: str = Field(..., description="Log source, e.g. auth.log, nginx/access.log.")
    event_type: str = Field(..., description="Canonical event type, e.g. ssh_failed_login.")
    payload: Dict[str, Any] = Field(..., description="Arbitrary JSON payload with event details.")

class EventOut(EventIn):
    id: int = Field(..., description="Database primary key.")
    prev_hash: Optional[str] = Field(None, description="Hash of the previous event in the chain.")
    cur_hash: str = Field(..., description="SHA-256 hash linking this event to the chain.")
    signature_verified: bool = Field(
        False, description="True if the agent's Ed25519 signature verified on receipt."
    )
    signer_pubkey: Optional[str] = Field(
        None, description="Base64 Ed25519 public key that signed the event (if any)."
    )

class HeartbeatIn(BaseModel):
    agent_id: str
    boot_id: str
    sequence: int
    sent_at_utc: datetime
    last_event_sequence: Optional[int] = None
    last_event_hash: Optional[str] = None
    agent_health: str
    signature: str
