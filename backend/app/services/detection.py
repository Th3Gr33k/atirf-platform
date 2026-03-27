from typing import Dict, List

from app.services.enrichment import MITRE_MAP


SEVERITY_BASE = {
    "low": 10,
    "medium": 25,
    "high": 40,
    "critical": 55,
}

CRITICALITY_BONUS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}

IOC_BONUS = {
    "unknown": 0,
    "suspicious": 15,
    "malicious": 25,
}


RECOMMENDATIONS = {
    "powershell_encoded": [
        "Review parent-child process chain.",
        "Collect PowerShell operational logs and script block logs.",
        "Consider isolating the endpoint if additional indicators exist.",
    ],
    "office_spawns_script": [
        "Validate whether the document origin is trusted.",
        "Inspect email source or download vector.",
        "Acquire the original document for sandboxing.",
    ],
    "malicious_domain": [
        "Block the domain at DNS and proxy layers.",
        "Search for other hosts resolving the same domain.",
        "Review egress activity for exfiltration or staging.",
    ],
    "mailbox_rule_created": [
        "Review newly created mailbox rules and forwarding destinations.",
        "Validate the originating sign-in and MFA context.",
        "Search for additional inbox tampering or suspicious OAuth activity.",
    ],
    "critical_admin_activity": [
        "Validate whether the privileged activity was scheduled and approved.",
        "Review recent authentication history for the involved admin account.",
        "Collect related endpoint, identity, and change-management evidence.",
    ],
}


def _join_actions(keys: List[str]) -> str:
    actions: List[str] = []
    seen = set()
    for key in keys:
        for item in RECOMMENDATIONS.get(key, []):
            if item not in seen:
                seen.add(item)
                actions.append(item)
    return " ".join(actions)



def detect_alert(enriched_event: Dict) -> Dict | None:
    indicators: List[str] = []
    rationale: List[str] = []
    mitre: List[str] = []
    title = None

    process_name = (enriched_event.get("process_name") or "").lower()
    parent_process = (enriched_event.get("parent_process") or "").lower()
    command_line = (enriched_event.get("command_line") or "").lower()
    domain = (enriched_event.get("domain") or "").lower()
    reputation = enriched_event.get("ioc_reputation", "unknown")
    criticality = enriched_event.get("asset_criticality", "medium")
    severity = enriched_event.get("severity", "low")
    event_type = (enriched_event.get("event_type") or "").lower()
    user_privilege = enriched_event.get("user_privilege", "standard")

    if "powershell" in process_name and ("-enc" in command_line or "frombase64string" in command_line):
        indicators.append("powershell_encoded")
        rationale.append("PowerShell was executed with an encoded or obfuscated command line.")
        mitre.append(MITRE_MAP["powershell_encoded"])
        title = "Encoded PowerShell Execution"

    if parent_process in {"winword.exe", "excel.exe", "outlook.exe"} and process_name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
        indicators.append("office_spawns_script")
        rationale.append("An Office application spawned a scripting or shell process, which is a common phishing or macro execution pattern.")
        mitre.append(MITRE_MAP["office_spawns_script"])
        title = title or "Office Spawned Script Interpreter"

    if domain and reputation in {"suspicious", "malicious"}:
        indicators.append("malicious_domain")
        rationale.append(f"The endpoint communicated with a domain classified as {reputation}.")
        mitre.append(MITRE_MAP["malicious_domain"])
        title = title or "Suspicious External Domain Communication"

    if event_type == "mailbox_rule_created":
        indicators.append("mailbox_rule_created")
        rationale.append("A mailbox forwarding or rule creation event can indicate email collection or persistence after account compromise.")
        mitre.append(MITRE_MAP["mailbox_rule_created"])
        title = title or "Suspicious Mailbox Rule Creation"

    if criticality == "critical" and user_privilege == "admin" and event_type in {"authentication_success", "privileged_command", "service_install"}:
        indicators.append("critical_admin_activity")
        rationale.append("Privileged activity occurred on a critical asset and should be validated against approved administration activity.")
        mitre.append(MITRE_MAP["critical_admin_activity"])
        title = title or "Privileged Activity On Critical Asset"

    if not indicators:
        return None

    risk_score = (
        SEVERITY_BASE.get(severity, 10)
        + CRITICALITY_BONUS.get(criticality, 10)
        + IOC_BONUS.get(reputation, 0)
        + 10 * len(indicators)
        + int(enriched_event.get("novelty", 5))
    )
    risk_score = min(risk_score, 100)

    derived_severity = "low"
    if risk_score >= 81:
        derived_severity = "critical"
    elif risk_score >= 61:
        derived_severity = "high"
    elif risk_score >= 31:
        derived_severity = "medium"

    return {
        "title": title or "Suspicious Activity Detected",
        "severity": derived_severity,
        "risk_score": risk_score,
        "mitre_technique": ", ".join(sorted(set(mitre))),
        "ioc_reputation": reputation,
        "asset_criticality": criticality,
        "rationale": " ".join(rationale),
        "recommended_actions": _join_actions(indicators),
    }
