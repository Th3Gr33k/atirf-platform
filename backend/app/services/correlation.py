from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session

from app.config import settings
from app.models.entities import Alert, Incident, IncidentEvent
from app.services.summarizer import build_incident_summary


def correlate_alert(db: Session, alert: Alert) -> Incident:
    hostname = alert.event.hostname
    user = alert.event.user
    event_time = _parse_event_timestamp(alert.event.timestamp)
    cutoff = event_time - timedelta(minutes=settings.correlation_window_minutes)

    existing = (
        db.query(Incident)
        .filter(
            Incident.hostname == hostname,
            Incident.status == "open",
            Incident.created_at >= cutoff,
        )
        .order_by(Incident.id.desc())
        .first()
    )

    if existing and existing.user and user and existing.user != user:
        existing = None

    if existing:
        link = IncidentEvent(incident_id=existing.id, alert_id=alert.id)
        db.add(link)
        alerts = _alerts_for_incident(db, existing.id) + [alert]
        existing.risk_score = min(100, max(a.risk_score for a in alerts))
        existing.severity = _max_severity([a.severity for a in alerts])
        existing.summary = build_incident_summary(existing, alerts)
        db.commit()
        db.refresh(existing)
        return existing

    incident = Incident(
        title=f"Potential compromise on {hostname}",
        severity=alert.severity,
        risk_score=alert.risk_score,
        hostname=hostname,
        user=user,
        status="open",
        summary="",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    link = IncidentEvent(incident_id=incident.id, alert_id=alert.id)
    db.add(link)
    incident.summary = build_incident_summary(incident, [alert])
    db.commit()
    db.refresh(incident)
    return incident



def _alerts_for_incident(db: Session, incident_id: int) -> List[Alert]:
    links = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    return [db.query(Alert).filter(Alert.id == link.alert_id).first() for link in links if link.alert_id]



def _max_severity(severities: List[str]) -> str:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return sorted(severities, key=lambda s: order.get(s, 0), reverse=True)[0]


def _parse_event_timestamp(timestamp: str) -> datetime:
    if timestamp.endswith("Z"):
        timestamp = timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(timestamp)
