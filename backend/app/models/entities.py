from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    event_source = Column(String, nullable=False)
    hostname = Column(String, nullable=False)
    user = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="low")
    process_name = Column(String, nullable=True)
    parent_process = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    file_hash = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    url = Column(String, nullable=True)
    raw_log = Column(Text, nullable=True)
    normalized = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    alert = relationship("Alert", back_populates="event", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False, default=0)
    mitre_technique = Column(String, nullable=True)
    ioc_reputation = Column(String, nullable=True)
    asset_criticality = Column(String, nullable=True)
    rationale = Column(Text, nullable=True)
    recommended_actions = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    event = relationship("Event", back_populates="alert")
    incidents = relationship("IncidentEvent", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False, default=0)
    summary = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="open")
    nist_phase = Column(String, nullable=False, default="Detection and Analysis")
    owner = Column(String, nullable=True)
    disposition = Column(String, nullable=True)
    last_decision = Column(String, nullable=True)
    response_summary = Column(Text, nullable=True)
    hostname = Column(String, nullable=True)
    user = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    tasks = relationship("IncidentTask", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)

    incident = relationship("Incident", back_populates="incident_events")
    alert = relationship("Alert", back_populates="incidents")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    platform = Column(String, nullable=True)
    data_sources = Column(Text, nullable=True)
    detection_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Connector(Base):
    __tablename__ = "connectors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    source_type = Column(String, nullable=False, index=True)
    base_url = Column(String, nullable=False)
    auth_type = Column(String, nullable=False, default="none")
    credential_hint = Column(String, nullable=True)
    trust_level = Column(String, nullable=False, default="community")
    enabled = Column(Boolean, default=True)
    notes = Column(Text, nullable=True)
    last_sync_status = Column(String, nullable=True)
    last_sync_message = Column(Text, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    jobs = relationship("ConnectorJob", back_populates="connector", cascade="all, delete-orphan")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    author = Column(String, nullable=True)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    incident = relationship("Incident", back_populates="notes")


class IncidentTask(Base):
    __tablename__ = "incident_tasks"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    title = Column(String, nullable=False)
    owner = Column(String, nullable=True)
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime, default=utcnow)

    incident = relationship("Incident", back_populates="tasks")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    evidence_type = Column(String, nullable=False)
    source = Column(String, nullable=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    incident = relationship("Incident", back_populates="evidence")


class ConnectorJob(Base):
    __tablename__ = "connector_jobs"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(Integer, ForeignKey("connectors.id"), nullable=False)
    job_type = Column(String, nullable=False, default="sync")
    status = Column(String, nullable=False, default="queued")
    message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    connector = relationship("Connector", back_populates="jobs")


class NewsSource(Base):
    __tablename__ = "news_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    trust_level = Column(String, nullable=False, default="community")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
