from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, IPvAnyAddress


# ============================================================
# SOURCE
# ============================================================

class Source(BaseModel):
    asset_id: str
    asset_type: str
    hostname: str


# ============================================================
# NETWORK
# ============================================================

class Network(BaseModel):
    source_ip: Optional[IPvAnyAddress] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)

    destination_ip: Optional[IPvAnyAddress] = None
    destination_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535
    )

    protocol: Optional[str] = None


# ============================================================
# ACTOR
# ============================================================

class Actor(BaseModel):
    user_id: Optional[str] = None
    session_id: Optional[str] = None


# ============================================================
# EVENT DETAILS
# ============================================================

class EventDetails(BaseModel):
    category: str
    type: str
    action: str
    status: str


# ============================================================
# TARGET
# ============================================================

class Target(BaseModel):
    asset_id: Optional[str] = None
    resource: Optional[str] = None
    resource_type: Optional[str] = None


# ============================================================
# CONTEXT
# ============================================================

class Context(BaseModel):
    environment: str
    simulation: bool = True


# ============================================================
# COMMON EVENT SCHEMA
# ============================================================

class CommonEvent(BaseModel):

    event_id: str

    timestamp: datetime

    source: Source

    network: Network

    actor: Actor

    event: EventDetails

    target: Target

    # Flexible asset-specific information
    data: Dict[str, Any]

    context: Context