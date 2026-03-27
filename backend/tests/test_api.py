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
    add_incident_evidence,
    add_incident_note,
    add_incident_task,
    create_connector,
    create_news_source,
    delete_news_source,
    get_alerts,
    get_attack_techniques,
    get_connector_jobs,
    import_events,
    get_incident_copilot,
    get_connectors,
    sync_connectors,
    get_incidents,
    get_hypotheses,
    get_kev_live,
    get_news_live,
    get_news_sources,
    get_playbook_for_incident,
    get_playbooks,
    get_ransomware_live,
    get_ransomware_patterns,
    get_source_catalog,
    health,
    load_demo,
    metrics,
    readiness,
    reset_demo,
    seed_attack_catalog,
    seed_news_sources,
    update_news_source,
    get_decision_helper,
    update_incident_workflow,
    ingest_event,
)
from app.database import Base, SessionLocal, engine
from app.schemas import (
    ConnectorIn,
    EventImportIn,
    EventIn,
    IncidentDecisionIn,
    IncidentEvidenceIn,
    IncidentNoteIn,
    NewsSourceIn,
    IncidentTaskIn,
    IncidentWorkflowIn,
)


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


def test_ransomware_live_returns_status_without_crashing():
    result = get_ransomware_live()

    assert result["status"] in {"ok", "error", "disabled"}
    assert result["provider"] == "ransomware.live"


def test_kev_and_news_feeds_return_status_without_crashing():
    db = _db()
    try:
        kev = get_kev_live()
        news = get_news_live(db=db)
    finally:
        db.close()

    assert kev["status"] in {"ok", "error", "disabled"}
    assert kev["provider"] == "cisa-kev"
    assert news["status"] in {"ok", "error", "disabled"}
    assert news["provider"] == "cyber-news"


def test_playbook_and_decision_helper_for_incident():
    db = _db()
    try:
        seed_attack_catalog(db=db)
        load_demo(db=db)
        incidents = get_incidents(db=db)
        catalog = get_playbooks()
        playbook = get_playbook_for_incident(incident_id=incidents[0].id, db=db)
        decision = get_decision_helper(
            incident_id=incidents[0].id,
            payload=IncidentDecisionIn(
                confidence="high",
                business_criticality="high",
                privileged_identity_exposure=True,
                ransomware_impact_evidence=True,
            ),
            db=db,
        )
    finally:
        db.close()

    assert len(catalog["playbooks"]) >= 4
    assert playbook["status"] == "ok"
    assert playbook["incident_type"] in {"ransomware", "phishing-bec", "identity-compromise", "endpoint-intrusion", "generic-compromise"}
    assert decision["status"] == "ok"
    assert decision["recommended_decision"] in {"monitor", "investigate_further", "contain_partially", "contain_aggressively"}


def test_workflow_sync_and_import_helpers():
    db = _db()
    try:
        create_connector(
            payload=ConnectorIn(
                name="Demo TAXII",
                source_type="taxii",
                base_url="https://taxii.example.local",
            ),
            db=db,
        )
        sync = sync_connectors(db=db)
        jobs = get_connector_jobs(db=db)
        imported = import_events(
            payload=EventImportIn(
                records=[
                    EventIn(
                        timestamp="2026-03-26T13:00:01Z",
                        event_source="xdr",
                        hostname="LAB-WS-01",
                        user="analyst.user",
                        event_type="process_start",
                        severity="medium",
                        process_name="powershell.exe",
                        parent_process="WINWORD.EXE",
                        command_line="powershell.exe -enc SQBFAFgAIAAoTmV3LU9iamVjdA==",
                    )
                ]
            ),
            db=db,
        )
        incidents = get_incidents(db=db)
        updated = update_incident_workflow(
            incident_id=incidents[0].id,
            payload=IncidentWorkflowIn(
                status="investigating",
                nist_phase="Detection and Analysis",
                owner="tier1.analyst",
                disposition="confirmed",
                last_decision="investigate_further",
                response_summary="Initial triage completed and host scoped for further review.",
            ),
            db=db,
        )
    finally:
        db.close()

    assert sync["status"] == "completed"
    assert sync["jobs_succeeded"] >= 1
    assert len(jobs) >= 1
    assert imported["count"] == 1
    assert updated.status == "investigating"
    assert updated.owner == "tier1.analyst"


def test_notes_tasks_and_evidence_can_be_added_to_incident():
    db = _db()
    try:
        load_demo(db=db)
        incidents = get_incidents(db=db)
        incident_id = incidents[0].id
        note = add_incident_note(
            incident_id=incident_id,
            payload=IncidentNoteIn(author="lead.analyst", body="Confirmed suspicious execution chain and began scoping."),
            db=db,
        )
        task = add_incident_task(
            incident_id=incident_id,
            payload=IncidentTaskIn(title="Collect host triage", owner="tier2.ir", status="in-progress"),
            db=db,
        )
        evidence = add_incident_evidence(
            incident_id=incident_id,
            payload=IncidentEvidenceIn(
                evidence_type="domain",
                source="dnsfilter",
                description="Observed resolution to a suspicious or malicious domain tied to the incident timeline.",
            ),
            db=db,
        )
        note_id = note.id
        task_id = task.id
        evidence_id = evidence.id
    finally:
        db.close()

    assert note_id is not None
    assert task_id is not None
    assert evidence_id is not None


def test_news_sources_can_be_seeded_and_added():
    db = _db()
    try:
        seeded = seed_news_sources(db=db)
        source = create_news_source(
            payload=NewsSourceIn(
                name="Custom Threat Feed",
                url="https://example.com/security-feed.xml",
                trust_level="research",
                enabled=True,
            ),
            db=db,
        )
        updated = update_news_source(
            source_id=source.id,
            payload=NewsSourceIn(
                name="Custom Threat Feed Updated",
                url="https://example.com/security-feed.xml",
                trust_level="authoritative",
                enabled=False,
            ),
            db=db,
        )
        sources = get_news_sources(db=db)
        deleted = delete_news_source(source_id=source.id, db=db)
    finally:
        db.close()

    assert seeded["status"] == "seeded"
    assert source.id is not None
    assert updated.enabled is False
    assert len(sources) >= 1
    assert deleted["status"] == "deleted"
