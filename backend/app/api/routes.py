from pathlib import Path
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.entities import Alert, AttackTechnique, Connector, Event, Incident, IncidentEvent, NewsSource
from app.models.entities import IncidentEvidence, IncidentNote, IncidentTask
from app.schemas import (
    AlertOut,
    AttackTechniqueOut,
    BulkEventsIn,
    ConnectorIn,
    ConnectorJobOut,
    ConnectorOut,
    EventImportIn,
    EventIn,
    EventOut,
    IncidentDecisionIn,
    IncidentEvidenceIn,
    IncidentEvidenceOut,
    IncidentNoteIn,
    IncidentNoteOut,
    NewsSourceIn,
    NewsSourceOut,
    IncidentTaskIn,
    IncidentTaskOut,
    IncidentWorkflowIn,
    IncidentOut,
)
from app.security import require_api_key
from app.services.correlation import correlate_alert
from app.services.copilot import generate_incident_copilot_summary
from app.services.connector_jobs import list_connector_jobs, run_connector_sync_jobs
from app.services.detection import detect_alert
from app.services.enrichment import enrich_event
from app.services.external_intel import ensure_default_news_sources, get_cyber_news_overview, get_kev_overview
from app.services.hypothesis import build_incident_hypotheses
from app.services.normalizer import normalize_event
from app.services.playbooks import build_decision_support, get_incident_playbook, get_playbook_catalog
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


@router.get("/kev/live")
def get_kev_live(_: None = Depends(require_api_key)) -> dict:
    return get_kev_overview()


@router.get("/news/live")
def get_news_live(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    return get_cyber_news_overview(db)


@router.get("/news/sources", response_model=list[NewsSourceOut])
def get_news_sources(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return db.query(NewsSource).order_by(NewsSource.id.desc()).all()


@router.post("/news/sources/seed")
def seed_news_sources(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    created = ensure_default_news_sources(db)
    return {"status": "seeded", "created": created, "total": db.query(NewsSource).count()}


@router.post("/news/sources", response_model=NewsSourceOut)
def create_news_source(payload: NewsSourceIn, db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    source = NewsSource(**payload.model_dump())
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.patch("/news/sources/{source_id}", response_model=NewsSourceOut)
def update_news_source(
    source_id: int,
    payload: NewsSourceIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    source = db.query(NewsSource).filter(NewsSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="News source not found")

    for field, value in payload.model_dump().items():
        setattr(source, field, value)

    db.commit()
    db.refresh(source)
    return source


@router.delete("/news/sources/{source_id}")
def delete_news_source(
    source_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    source = db.query(NewsSource).filter(NewsSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="News source not found")

    db.delete(source)
    db.commit()
    return {"status": "deleted", "source_id": source_id}


@router.get("/playbooks")
def get_playbooks(_: None = Depends(require_api_key)) -> dict:
    return get_playbook_catalog()


@router.get("/playbooks/incident/{incident_id}")
def get_playbook_for_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    result = get_incident_playbook(db, incident_id)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@router.post("/playbooks/incident/{incident_id}/decision")
def get_decision_helper(
    incident_id: int,
    payload: IncidentDecisionIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    result = build_decision_support(db, incident_id, payload.model_dump())
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


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


@router.post("/connectors/sync")
def sync_connectors(db: Session = Depends(get_db), _: None = Depends(require_api_key)) -> dict:
    return run_connector_sync_jobs(db)


@router.get("/connectors/jobs", response_model=list[ConnectorJobOut])
def get_connector_jobs(db: Session = Depends(get_db), _: None = Depends(require_api_key)):
    return list_connector_jobs(db)


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
        "notes": [IncidentNoteOut.model_validate(note) for note in incident.notes],
        "tasks": [IncidentTaskOut.model_validate(task) for task in incident.tasks],
        "evidence": [IncidentEvidenceOut.model_validate(item) for item in incident.evidence],
    }


@router.patch("/incidents/{incident_id}/workflow", response_model=IncidentOut)
def update_incident_workflow(
    incident_id: int,
    payload: IncidentWorkflowIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)

    db.commit()
    db.refresh(incident)
    return incident


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
        "synced_connectors": db.query(Connector).filter(Connector.last_sync_status == "ok").count(),
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
    db.query(NewsSource).delete()
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


@router.post("/imports/events")
def import_events(
    payload: EventImportIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    results = [ingest_event(record, db) for record in payload.records]
    return {"status": "imported", "count": len(results), "results": results}


@router.post("/imports/events-file")
async def import_events_file(
    file: UploadFile,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict:
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON files are supported.")

    raw = await file.read()
    try:
        records = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {exc.msg}") from exc

    if not isinstance(records, list):
        raise HTTPException(status_code=400, detail="JSON file must contain a list of event objects.")

    results = [ingest_event(EventIn(**record), db) for record in records]
    return {"status": "imported", "filename": file.filename, "count": len(results), "results": results}


@router.post("/incidents/{incident_id}/notes", response_model=IncidentNoteOut)
def add_incident_note(
    incident_id: int,
    payload: IncidentNoteIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    note = IncidentNote(incident_id=incident_id, **payload.model_dump())
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.post("/incidents/{incident_id}/tasks", response_model=IncidentTaskOut)
def add_incident_task(
    incident_id: int,
    payload: IncidentTaskIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    task = IncidentTask(incident_id=incident_id, **payload.model_dump())
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.post("/incidents/{incident_id}/evidence", response_model=IncidentEvidenceOut)
def add_incident_evidence(
    incident_id: int,
    payload: IncidentEvidenceIn,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = IncidentEvidence(incident_id=incident_id, **payload.model_dump())
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence
