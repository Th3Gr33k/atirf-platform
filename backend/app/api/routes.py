from pathlib import Path
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.entities import Alert, AttackTechnique, Connector, Event, Incident, IncidentEvent
from app.schemas import (
    AlertOut,
    AttackTechniqueOut,
    BulkEventsIn,
    ConnectorIn,
    ConnectorOut,
    EventIn,
    EventOut,
    IncidentOut,
)
from app.security import require_api_key
from app.services.correlation import correlate_alert
from app.services.copilot import generate_incident_copilot_summary
from app.services.detection import detect_alert
from app.services.enrichment import enrich_event
from app.services.hypothesis import build_incident_hypotheses
from app.services.normalizer import normalize_event
from app.services.ransomware_live import get_live_group_detail, get_live_ransomware_overview

router = APIRouter(prefix="/api")

DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "sample_logs"
ATTACK_DIR = Path(__file__).resolve().parents[3] / "data" / "attack"
INTEL_DIR = Path(__file__).resolve().parents[3] / "data" / "intel"


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "environment": settings.environment, "version": settings.app_version}


@router.get("/ready")
def readiness(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "ok"}


@router.get("/attack/techniques", response_model=list[AttackTechniqueOut])
def get_attack_techniques(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(AttackTechnique).order_by(AttackTechnique.technique_id.asc()).all()


@router.post("/attack/seed")
def seed_attack_catalog(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    seed_path = ATTACK_DIR / "mitre_attack_seed.json"
    with seed_path.open("r", encoding="utf-8") as handle:
        records = json.load(handle)

    created = 0
    for record in records:
        existing = db.query(AttackTechnique).filter(AttackTechnique.technique_id == record["technique_id"]).first()
        if existing:
            continue
        db.add(AttackTechnique(**record))
        created += 1

    db.commit()
    return {"status": "seeded", "created": created, "total": db.query(AttackTechnique).count()}


@router.get("/intel/source-catalog")
def get_source_catalog(_: None = Depends(require_api_key)) -> dict:
    source_path = INTEL_DIR / "source_catalog.json"
    with source_path.open("r", encoding="utf-8") as handle:
        return {"sources": json.load(handle)}


@router.get("/ransomware/patterns")
def get_ransomware_patterns(_: None = Depends(require_api_key)) -> dict:
    pattern_path = INTEL_DIR / "ransomware_patterns.json"
    with pattern_path.open("r", encoding="utf-8") as handle:
        return {"patterns": json.load(handle)}


@router.get("/ransomware/live")
def get_ransomware_live(_: None = Depends(require_api_key)) -> dict:
    return get_live_ransomware_overview()


@router.get("/ransomware/live/group/{group_name}")
def get_ransomware_live_group(group_name: str, _: None = Depends(require_api_key)) -> dict:
    return get_live_group_detail(group_name)


@router.get("/hypotheses")
def get_hypotheses(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    return {"incidents": build_incident_hypotheses(db)}


@router.get("/copilot/incident/{incident_id}")
def get_incident_copilot(
    incident_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    result = generate_incident_copilot_summary(db, incident_id)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@router.get("/connectors", response_model=list[ConnectorOut])
def get_connectors(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(Connector).order_by(Connector.id.desc()).all()


@router.post("/connectors", response_model=ConnectorOut)
def create_connector(payload: ConnectorIn, db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    connector = Connector(**payload.model_dump())
    db.add(connector)
    db.commit()
    db.refresh(connector)
    return connector


@router.post("/events/ingest", response_model=dict)
def ingest_event(
    payload: EventIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
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
def bulk_ingest(
    payload: BulkEventsIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    results = []
    for event in payload.events:
        results.append(ingest_event(event, db))
    return {"status": "processed", "count": len(results), "results": results}


@router.get("/events", response_model=list[EventOut])
def get_events(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(Event).order_by(Event.id.desc()).all()


@router.get("/alerts", response_model=list[AlertOut])
def get_alerts(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(Alert).order_by(Alert.id.desc()).all()


@router.get("/incidents", response_model=list[IncidentOut])
def get_incidents(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(Incident).order_by(Incident.id.desc()).all()


@router.get("/incidents/{incident_id}")
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
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
def metrics(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
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
        "connectors": db.query(Connector).count(),
        "attack_techniques": db.query(AttackTechnique).count(),
        "severity_breakdown": severity_breakdown,
        "mitre_counts": mitre_counts,
    }


@router.post("/demo/reset")
def reset_demo(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    if not settings.enable_demo_routes:
        raise HTTPException(status_code=404, detail="Demo routes are disabled.")
    db.query(IncidentEvent).delete()
    db.query(Alert).delete()
    db.query(Incident).delete()
    db.query(Event).delete()
    db.query(Connector).delete()
    db.query(AttackTechnique).delete()
    db.commit()
    return {"status": "reset"}


@router.post("/demo/load")
def load_demo(
    dataset: str = "demo_events.json",
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    if not settings.enable_demo_routes:
        raise HTTPException(status_code=404, detail="Demo routes are disabled.")
    if "/" in dataset or "\\" in dataset or not dataset.endswith(".json"):
        raise HTTPException(status_code=400, detail="Invalid dataset name.")

    demo_path = DATA_DIR / dataset
    if not demo_path.exists():
        raise HTTPException(status_code=404, detail="Demo data not found")

    with demo_path.open("r", encoding="utf-8") as f:
        records = json.load(f)

    results = []
    for record in records:
        payload = EventIn(**record)
        results.append(ingest_event(payload, db))

    return {"status": "loaded", "dataset": dataset, "count": len(results), "results": results}
