from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


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

    model_config = ConfigDict(from_attributes=True)


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

    model_config = ConfigDict(from_attributes=True)


class IncidentOut(BaseModel):
    id: int
    title: str
    severity: str
    risk_score: float
    summary: Optional[str] = None
    status: str
    hostname: Optional[str] = None
    user: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AttackTechniqueOut(BaseModel):
    id: int
    technique_id: str
    name: str
    tactic: str
    platform: Optional[str] = None
    data_sources: Optional[str] = None
    detection_notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ConnectorIn(BaseModel):
    name: str
    source_type: str
    base_url: str
    auth_type: str = "none"
    credential_hint: Optional[str] = None
    trust_level: str = "community"
    enabled: bool = True
    notes: Optional[str] = None


class ConnectorOut(ConnectorIn):
    id: int

    model_config = ConfigDict(from_attributes=True)
