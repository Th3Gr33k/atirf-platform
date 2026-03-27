from typing import Dict

ASSET_CRITICALITY = {
    "LAB-EDITOR-01": "high",
    "LAB-DC-01": "critical",
    "LAB-LAPTOP-01": "medium",
}

MALICIOUS_DOMAINS = {
    "bootstrap-updates.example": "malicious",
    "login-verify.example": "suspicious",
    "secure-portal.example": "suspicious",
    "fileshare-auth.example": "malicious",
}

MITRE_MAP = {
    "powershell_encoded": "T1059.001",
    "office_spawns_script": "T1204",
    "malicious_domain": "T1071.001",
    "mailbox_rule_created": "T1114.003",
    "critical_admin_activity": "T1078",
}


def enrich_event(event: Dict) -> Dict:
    enriched = {**event}
    hostname = event.get("hostname")
    domain = event.get("domain")
    user = (event.get("user") or "").lower()

    enriched["asset_criticality"] = ASSET_CRITICALITY.get(hostname, "medium")
    enriched["ioc_reputation"] = MALICIOUS_DOMAINS.get(domain, "unknown") if domain else "unknown"
    enriched["user_privilege"] = "admin" if user in {"administrator", "itadmin", "svc-backup"} else "standard"
    enriched["novelty"] = 15 if domain in MALICIOUS_DOMAINS else 5
    return enriched
