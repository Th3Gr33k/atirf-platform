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
    nist_phase: str
    owner: Optional[str] = None
    disposition: Optional[str] = None
    last_decision: Optional[str] = None
    response_summary: Optional[str] = None
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
    last_sync_status: Optional[str] = None
    last_sync_message: Optional[str] = None
    last_sync_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentDecisionIn(BaseModel):
    incident_type: Optional[str] = None
    confidence: str = "medium"
    business_criticality: str = "medium"
    privileged_identity_exposure: bool = False
    lateral_movement_evidence: bool = False
    exfiltration_evidence: bool = False
    ransomware_impact_evidence: bool = False
    external_exposure: bool = False


class IncidentWorkflowIn(BaseModel):
    status: Optional[str] = None
    nist_phase: Optional[str] = None
    owner: Optional[str] = None
    disposition: Optional[str] = None
    last_decision: Optional[str] = None
    response_summary: Optional[str] = None


class EventImportIn(BaseModel):
    records: List[EventIn] = Field(default_factory=list)


class IncidentNoteIn(BaseModel):
    author: Optional[str] = None
    body: str


class IncidentNoteOut(IncidentNoteIn):
    id: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentTaskIn(BaseModel):
    title: str
    owner: Optional[str] = None
    status: str = "open"


class IncidentTaskOut(IncidentTaskIn):
    id: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentEvidenceIn(BaseModel):
    evidence_type: str
    source: Optional[str] = None
    description: str


class IncidentEvidenceOut(IncidentEvidenceIn):
    id: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ConnectorJobOut(BaseModel):
    id: int
    connector_id: int
    job_type: str
    status: str
    message: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class NewsSourceIn(BaseModel):
    name: str
    url: str
    trust_level: str = "community"
    enabled: bool = True


class NewsSourceOut(NewsSourceIn):
    id: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
