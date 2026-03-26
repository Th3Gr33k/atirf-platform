from typing import List, Optional
from pydantic import BaseModel, Field


class EventIn(BaseModel):
    timestamp: str
    event_source: str
    hostname: str
    user: Optional[str] = None
    ip_address: Optional[str] = None
    event_type: str
    severity: str = "low"
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    raw_log: Optional[str] = None


class BulkEventsIn(BaseModel):
    events: List[EventIn] = Field(default_factory=list)


class EventOut(EventIn):
    id: int
    normalized: bool

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: int
    event_id: int
    title: str
    severity: str
    risk_score: float
    mitre_technique: Optional[str] = None
    ioc_reputation: Optional[str] = None
    asset_criticality: Optional[str] = None
    rationale: Optional[str] = None
    recommended_actions: Optional[str] = None

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: int
    title: str
    severity: str
    risk_score: float
    summary: Optional[str] = None
    status: str
    hostname: Optional[str] = None
    user: Optional[str] = None

    class Config:
        from_attributes = True
