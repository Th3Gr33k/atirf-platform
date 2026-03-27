from pathlib import Path
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models.entities import Alert, Event, Incident, IncidentEvent
from app.schemas import AlertOut, BulkEventsIn, EventIn, EventOut, IncidentOut
from app.services.correlation import correlate_alert
from app.services.detection import detect_alert
from app.services.enrichment import enrich_event
from app.services.normalizer import normalize_event

router = APIRouter(prefix="/api")

DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "sample_logs"


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.post("/events/ingest", response_model=dict)
def ingest_event(payload: EventIn, db: Session = Depends(get_db)) -> dict:
    normalized = normalize_event(payload.model_dump())
    enriched = enrich_event(normalized)

    event = Event(**normalized)
    db.add(event)
    db.commit()
    db.refresh(event)

    alert_data = detect_alert(enriched)
    incident_id = None
    alert_id = None

    if alert_data:
        alert = Alert(event_id=event.id, **alert_data)
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id
        incident = correlate_alert(db, alert)
        incident_id = incident.id

    return {
        "status": "processed",
        "event_id": event.id,
        "alert_id": alert_id,
        "incident_id": incident_id,
    }


@router.post("/events/bulk")
def bulk_ingest(payload: BulkEventsIn, db: Session = Depends(get_db)) -> dict:
    results = []
    for event in payload.events:
        results.append(ingest_event(event, db))
    return {"status": "processed", "count": len(results), "results": results}


@router.get("/events", response_model=list[EventOut])
def get_events(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.id.desc()).all()


@router.get("/alerts", response_model=list[AlertOut])
def get_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.id.desc()).all()


@router.get("/incidents", response_model=list[IncidentOut])
def get_incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.id.desc()).all()


@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: int, db: Session = Depends(get_db)) -> dict:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    links = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    alerts = [db.query(Alert).filter(Alert.id == link.alert_id).first() for link in links]

    return {
        "incident": IncidentOut.model_validate(incident),
        "alerts": [AlertOut.model_validate(a) for a in alerts if a],
    }


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> dict:
    alerts = db.query(Alert).all()
    incidents = db.query(Incident).all()
    events = db.query(Event).all()

    severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for alert in alerts:
        severity_breakdown[alert.severity] = severity_breakdown.get(alert.severity, 0) + 1

    mitre_counts: dict[str, int] = {}
    for alert in alerts:
        if alert.mitre_technique:
            for t in [x.strip() for x in alert.mitre_technique.split(",")]:
                mitre_counts[t] = mitre_counts.get(t, 0) + 1

    return {
        "events": len(events),
        "alerts": len(alerts),
        "incidents": len(incidents),
        "severity_breakdown": severity_breakdown,
        "mitre_counts": mitre_counts,
    }


@router.post("/demo/reset")
def reset_demo(db: Session = Depends(get_db)) -> dict:
    db.query(IncidentEvent).delete()
    db.query(Alert).delete()
    db.query(Incident).delete()
    db.query(Event).delete()
    db.commit()
    return {"status": "reset"}


@router.post("/demo/load")
def load_demo(db: Session = Depends(get_db)) -> dict:
    demo_path = DATA_DIR / "demo_events.json"
    if not demo_path.exists():
        raise HTTPException(status_code=404, detail="Demo data not found")

    with demo_path.open("r", encoding="utf-8") as f:
        records = json.load(f)

    results = []
    for record in records:
        payload = EventIn(**record)
        results.append(ingest_event(payload, db))

    return {"status": "loaded", "count": len(results), "results": results}
