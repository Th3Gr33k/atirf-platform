from __future__ import annotations

from pathlib import Path
import json

from sqlalchemy.orm import Session

from app.models.entities import Alert, Incident, IncidentEvent


PLAYBOOK_PATH = Path(__file__).resolve().parents[3] / "data" / "intel" / "incident_playbooks.json"


def get_playbook_catalog() -> dict:
    return {"playbooks": json.loads(PLAYBOOK_PATH.read_text(encoding="utf-8"))}


def get_incident_playbook(db: Session, incident_id: int) -> dict:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"status": "not_found", "message": "Incident not found."}

    alerts = _alerts_for_incident(db, incident_id)
    incident_type = infer_incident_type(alerts)
    catalog = json.loads(PLAYBOOK_PATH.read_text(encoding="utf-8"))
    playbook = next((item for item in catalog if item["incident_type"] == incident_type), None)

    return {
        "status": "ok",
        "incident_id": incident.id,
        "incident_type": incident_type,
        "playbook": playbook,
    }


def build_decision_support(db: Session, incident_id: int, inputs: dict | None = None) -> dict:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"status": "not_found", "message": "Incident not found."}

    alerts = _alerts_for_incident(db, incident_id)
    incident_type = (inputs or {}).get("incident_type") or infer_incident_type(alerts)
    risk_score = incident.risk_score
    severity = incident.severity
    confidence = (inputs or {}).get("confidence", "medium")
    business_criticality = (inputs or {}).get("business_criticality", "medium")
    privileged = bool((inputs or {}).get("privileged_identity_exposure", False))
    lateral = bool((inputs or {}).get("lateral_movement_evidence", False))
    exfil = bool((inputs or {}).get("exfiltration_evidence", False))
    ransomware = bool((inputs or {}).get("ransomware_impact_evidence", False))
    external = bool((inputs or {}).get("external_exposure", False))

    recommended_decision = "investigate_further"
    if ransomware or exfil or privileged or lateral or severity in {"high", "critical"} or risk_score >= 80:
        recommended_decision = "contain_aggressively"
    elif external or risk_score >= 60 or confidence == "high":
        recommended_decision = "contain_partially"
    elif confidence == "low" and risk_score < 35:
        recommended_decision = "monitor"

    return {
        "status": "ok",
        "incident_id": incident.id,
        "incident_type": incident_type,
        "recommended_decision": recommended_decision,
        "decision_rationale": _decision_rationale(
            confidence,
            business_criticality,
            privileged,
            lateral,
            exfil,
            ransomware,
            external,
            severity,
            risk_score,
        ),
        "nistr_phase": _nist_phase_for_decision(recommended_decision),
        "suggested_actions": _suggested_actions(incident_type, recommended_decision),
    }


def infer_incident_type(alerts: list[Alert]) -> str:
    techniques = {
        technique.strip()
        for alert in alerts
        for technique in (alert.mitre_technique or "").split(",")
        if technique.strip()
    }
    titles = " ".join((alert.title or "").lower() for alert in alerts)

    if {"T1486", "T1490", "T1489"} & techniques or "ransom" in titles:
        return "ransomware"
    if "mailbox" in titles or "forwarding rule" in titles or "phish" in titles or "T1114.003" in techniques or "T1566" in techniques:
        return "phishing-bec"
    if "T1078" in techniques:
        return "identity-compromise"
    if "powershell" in titles or "script" in titles or "T1059.001" in techniques or "T1204" in techniques:
        return "endpoint-intrusion"
    return "generic-compromise"


def _alerts_for_incident(db: Session, incident_id: int) -> list[Alert]:
    links = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    return [db.query(Alert).filter(Alert.id == link.alert_id).first() for link in links if link.alert_id]


def _decision_rationale(confidence, criticality, privileged, lateral, exfil, ransomware, external, severity, risk_score) -> list[str]:
    reasons = [
        f"Current confidence is {confidence}.",
        f"Business criticality is {criticality}.",
        f"Observed incident severity is {severity} with risk score {int(risk_score)}.",
    ]
    if privileged:
        reasons.append("Privileged identity exposure is present.")
    if lateral:
        reasons.append("There is evidence of lateral movement.")
    if exfil:
        reasons.append("Potential exfiltration evidence is present.")
    if ransomware:
        reasons.append("Ransomware-impact indicators are present.")
    if external:
        reasons.append("The incident involves externally exposed systems or public-facing access.")
    return reasons


def _nist_phase_for_decision(decision: str) -> str:
    if decision in {"monitor", "investigate_further"}:
        return "Detection and Analysis"
    return "Containment, Eradication, and Recovery"


def _suggested_actions(incident_type: str, decision: str) -> list[str]:
    base = {
        "monitor": [
            "Collect additional corroborating evidence before disruptive action.",
            "Track related alerts and expand entity pivots across hosts, identities, and domains.",
        ],
        "investigate_further": [
            "Validate scope, supporting telemetry, and ATT&CK sequence progression.",
            "Preserve evidence and identify affected assets, accounts, and infrastructure.",
        ],
        "contain_partially": [
            "Apply scoped containment to the affected asset, identity, or destination.",
            "Preserve forensic context while reducing adversary freedom of movement.",
        ],
        "contain_aggressively": [
            "Isolate affected endpoints or accounts immediately.",
            "Block active destinations, revoke sessions, and protect critical systems and backups.",
        ],
    }[decision]

    overlays = {
        "ransomware": [
            "Validate backup integrity and monitor for service stop or shadow-copy deletion behavior.",
            "Hunt for lateral movement and encryption staging on adjacent systems.",
        ],
        "phishing-bec": [
            "Review mailbox rules, OAuth grants, and sign-in history.",
            "Identify recipients, follow-on clicks, and identity-provider anomalies.",
        ],
        "identity-compromise": [
            "Revoke sessions, inspect privileged use, and review tenant-wide sign-in activity.",
            "Check role assignments, MFA events, and newly created credentials or tokens.",
        ],
        "endpoint-intrusion": [
            "Collect process lineage, persistence artifacts, and related network activity.",
            "Hunt sibling endpoints for matching command lines, hashes, or destinations.",
        ],
        "generic-compromise": [
            "Expand entity pivots and collect missing telemetry needed to determine scope and stage.",
        ],
    }

    return base + overlays.get(incident_type, [])
