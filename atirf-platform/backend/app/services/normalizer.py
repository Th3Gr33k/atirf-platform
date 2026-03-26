from typing import Dict


def normalize_event(event: Dict) -> Dict:
    normalized = {**event}
    normalized["event_source"] = str(event.get("event_source", "unknown")).lower().strip()
    normalized["event_type"] = str(event.get("event_type", "generic")).lower().strip()
    normalized["severity"] = str(event.get("severity", "low")).lower().strip()

    for key in ["hostname", "user", "process_name", "parent_process", "domain"]:
        value = normalized.get(key)
        if isinstance(value, str):
            normalized[key] = value.strip()

    if normalized.get("domain"):
        normalized["domain"] = normalized["domain"].lower()

    normalized["normalized"] = True
    return normalized
