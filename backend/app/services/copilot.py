from __future__ import annotations

import json
from urllib import error, request

from sqlalchemy.orm import Session

from app.config import settings
from app.models.entities import Alert, AttackTechnique, Incident, IncidentEvent
from app.services.hypothesis import build_incident_hypotheses


def generate_incident_copilot_summary(db: Session, incident_id: int) -> dict:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"status": "not_found", "message": "Incident not found."}

    alerts = _alerts_for_incident(db, incident_id)
    if not alerts:
        return {"status": "no_evidence", "message": "No alerts are linked to this incident yet."}

    hypotheses = next(
        (item for item in build_incident_hypotheses(db) if item["incident_id"] == incident_id),
        {"observed_techniques": [], "top_hypotheses": []},
    )

    context = _build_context(db, incident, alerts, hypotheses)

    if not settings.ollama_enabled:
        return {
            "status": "disabled",
            "provider": "ollama",
            "model": settings.ollama_model,
            "context": context,
            "message": "Ollama copilot is disabled. Enable ATIRF_OLLAMA_ENABLED and run Ollama locally.",
        }

    prompt = _build_prompt(context)

    try:
        response = _call_ollama(prompt)
    except Exception as exc:  # pragma: no cover - error path is runtime-dependent
        return {
            "status": "error",
            "provider": "ollama",
            "model": settings.ollama_model,
            "context": context,
            "message": f"Ollama request failed: {exc}",
        }

    return {
        "status": "ok",
        "provider": "ollama",
        "model": settings.ollama_model,
        "context": context,
        "analysis": response,
    }


def _alerts_for_incident(db: Session, incident_id: int) -> list[Alert]:
    links = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    return [db.query(Alert).filter(Alert.id == link.alert_id).first() for link in links if link.alert_id]


def _build_context(db: Session, incident: Incident, alerts: list[Alert], hypotheses: dict) -> dict:
    technique_ids = sorted(
        {
            technique.strip()
            for alert in alerts
            for technique in (alert.mitre_technique or "").split(",")
            if technique.strip()
        }
    )
    technique_details = []
    for technique_id in technique_ids:
        mapped = db.query(AttackTechnique).filter(AttackTechnique.technique_id == technique_id).first()
        if mapped:
            technique_details.append(
                {
                    "technique_id": mapped.technique_id,
                    "name": mapped.name,
                    "tactic": mapped.tactic,
                    "data_sources": mapped.data_sources,
                }
            )

    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "hostname": incident.hostname,
            "user": incident.user,
            "summary": incident.summary,
        },
        "alerts": [
            {
                "title": alert.title,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "mitre_technique": alert.mitre_technique,
                "rationale": alert.rationale,
                "recommended_actions": alert.recommended_actions,
            }
            for alert in alerts
        ],
        "techniques": technique_details,
        "observed_techniques": hypotheses.get("observed_techniques", []),
        "top_hypotheses": hypotheses.get("top_hypotheses", []),
    }


def _build_prompt(context: dict) -> str:
    return (
        "You are an incident-response copilot for defenders. "
        "Use only the provided incident evidence, ATT&CK mappings, and ranked hypotheses. "
        "Do not invent facts. "
        "Return four short sections titled: Assessment, Most Likely Attack Pattern, Evidence, Next Steps.\n\n"
        f"Incident context:\n{json.dumps(context, indent=2)}"
    )


def _call_ollama(prompt: str) -> str:
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    req = request.Request(
        f"{settings.ollama_host.rstrip('/')}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=settings.ollama_timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc

    text = body.get("response", "").strip()
    if not text:
        raise RuntimeError("Empty response from Ollama.")
    return text
