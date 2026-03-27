import os
from pathlib import Path
import sys

os.environ["ATIRF_DATABASE_URL"] = "sqlite:////tmp/atirf_test.db"
os.environ["ATIRF_ENABLE_DEMO_ROUTES"] = "true"

db_path = Path("/tmp/atirf_test.db")
if db_path.exists():
    db_path.unlink()

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.routes import (
    create_connector,
    get_alerts,
    get_attack_techniques,
    get_incident_copilot,
    get_connectors,
    get_incidents,
    get_hypotheses,
    get_ransomware_live,
    get_ransomware_patterns,
    get_source_catalog,
    health,
    load_demo,
    metrics,
    readiness,
    reset_demo,
    seed_attack_catalog,
    ingest_event,
)
from app.database import Base, SessionLocal, engine
from app.schemas import ConnectorIn, EventIn


Base.metadata.create_all(bind=engine)


def _db():
    return SessionLocal()


def setup_function():
    db = _db()
    try:
        reset_demo(db=db)
    finally:
        db.close()


def test_health_and_readiness():
    db = _db()
    try:
        health_payload = health()
        ready_payload = readiness(db=db)
    finally:
        db.close()

    assert health_payload["status"] == "ok"
    assert ready_payload["status"] == "ready"


def test_ingest_creates_alert_and_incident():
    db = _db()
    try:
        payload = EventIn(
            timestamp="2026-03-26T13:00:01Z",
            event_source="XDR",
            hostname="TEST-PC-01",
            user="test.user",
            event_type="process_start",
            severity="medium",
            process_name="powershell.exe",
            parent_process="WINWORD.EXE",
            command_line="powershell.exe -enc SQBFAFgAIAAoTmV3LU9iamVjdA==",
        )

        result = ingest_event(payload=payload, db=db)
        alerts = get_alerts(db=db)
        incidents = get_incidents(db=db)
    finally:
        db.close()

    assert result["alert_id"] is not None
    assert result["incident_id"] is not None
    assert len(alerts) == 1
    assert len(incidents) == 1


def test_demo_load_populates_metrics():
    db = _db()
    try:
        seed_attack_catalog(db=db)
        load = load_demo(db=db)
        metrics_payload = metrics(db=db)
        incidents = get_incidents(db=db)
        hypotheses = get_hypotheses(db=db)
    finally:
        db.close()

    assert load["count"] >= 4
    assert metrics_payload["events"] >= 4
    assert metrics_payload["alerts"] >= 3
    assert len(incidents) >= 1
    assert len(hypotheses["incidents"]) >= 1


def test_attack_seed_and_connector_creation():
    db = _db()
    try:
        seeded = seed_attack_catalog(db=db)
        techniques = get_attack_techniques(db=db)
        connector = create_connector(
            payload=ConnectorIn(
                name="Community MISP",
                source_type="misp",
                base_url="https://misp.example.local",
                auth_type="api_key",
                credential_hint="env:MISP_API_KEY",
                notes="Shared threat-sharing instance for validation.",
            ),
            db=db,
        )
        connectors = get_connectors(db=db)
        source_catalog = get_source_catalog()
        patterns = get_ransomware_patterns()
        metrics_payload = metrics(db=db)
    finally:
        db.close()

    assert seeded["created"] >= 1
    assert len(techniques) >= 10
    assert connector.source_type == "misp"
    assert len(connectors) == 1
    assert len(source_catalog["sources"]) >= 5
    assert len(patterns["patterns"]) >= 3
    assert metrics_payload["connectors"] == 1
    assert metrics_payload["attack_techniques"] >= 10


def test_incident_copilot_returns_grounded_disabled_state():
    db = _db()
    try:
        seed_attack_catalog(db=db)
        load_demo(db=db)
        incidents = get_incidents(db=db)
        result = get_incident_copilot(incident_id=incidents[0].id, db=db)
    finally:
        db.close()

    assert result["status"] == "disabled"
    assert result["provider"] == "ollama"
    assert len(result["context"]["alerts"]) >= 1


def test_ransomware_live_returns_disabled_state_by_default():
    result = get_ransomware_live()

    assert result["status"] == "disabled"
    assert result["provider"] == "ransomware.live"
