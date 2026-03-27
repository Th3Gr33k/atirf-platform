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
    hostname = Column(String, nullable=True)
    user = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")


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
    created_at = Column(DateTime, default=utcnow)
