from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.entities import Alert, Incident, IncidentEvent


PATTERN_PATH = Path(__file__).resolve().parents[3] / "data" / "intel" / "ransomware_patterns.json"


def build_incident_hypotheses(db: Session) -> list[dict]:
    patterns = json.loads(PATTERN_PATH.read_text(encoding="utf-8"))
    incidents = db.query(Incident).order_by(Incident.id.desc()).all()
    results: list[dict] = []

    for incident in incidents:
        alerts = _alerts_for_incident(db, incident.id)
        observed = sorted(
            {
                technique.strip()
                for alert in alerts
                for technique in (alert.mitre_technique or "").split(",")
                if technique.strip()
            }
        )
        ranked = []
        for pattern in patterns:
            expected = set(pattern.get("likely_techniques", []))
            overlap = sorted(expected.intersection(observed))
            score = round((len(overlap) / len(expected)) * 100, 1) if expected else 0.0
            ranked.append(
                {
                    "family": pattern["family"],
                    "confidence": score,
                    "matched_techniques": overlap,
                    "missing_techniques": sorted(expected.difference(observed)),
                    "operator_notes": pattern.get("operator_notes", ""),
                }
            )

        ranked.sort(key=lambda item: item["confidence"], reverse=True)
        results.append(
            {
                "incident_id": incident.id,
                "incident_title": incident.title,
                "observed_techniques": observed,
                "top_hypotheses": ranked[:3],
            }
        )

    return results


def _alerts_for_incident(db: Session, incident_id: int) -> list[Alert]:
    links = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    return [db.query(Alert).filter(Alert.id == link.alert_id).first() for link in links if link.alert_id]
