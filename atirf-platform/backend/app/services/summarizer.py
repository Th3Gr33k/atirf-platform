from typing import List


def build_incident_summary(incident, alerts: List) -> str:
    techniques = sorted({a.mitre_technique for a in alerts if a.mitre_technique})
    titles = [a.title for a in alerts]
    host = incident.hostname or "unknown host"
    user = incident.user or "unknown user"

    narrative = [
        f"ATIRF correlated {len(alerts)} alert(s) involving host {host} and user {user}.",
        f"Observed activity includes: {', '.join(titles)}.",
    ]

    if techniques:
        narrative.append(f"Likely ATT&CK techniques: {'; '.join(techniques)}.")

    highest = max(alerts, key=lambda a: a.risk_score)
    narrative.append(
        f"Highest risk indicator: {highest.title} with score {highest.risk_score:.0f}. Rationale: {highest.rationale}"
    )
    narrative.append(
        "Recommended analyst workflow: validate origin of the triggering document or process, review outbound network activity, hunt for similar behavior across additional endpoints, and contain the device if malicious execution is confirmed."
    )

    return " ".join(narrative)
