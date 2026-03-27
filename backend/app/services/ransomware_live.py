from __future__ import annotations

import json
from urllib import error, parse, request

from app.config import settings


def get_live_ransomware_overview() -> dict:
    if not settings.ransomware_live_enabled:
        return {
            "status": "disabled",
            "message": "Live ransomware feed is disabled. Enable ATIRF_RANSOMWARE_LIVE_ENABLED to fetch ransomware.live data.",
            "provider": "ransomware.live",
            "base_url": settings.ransomware_live_base_url,
        }

    try:
        info = _fetch_json("/info")
        recent_victims = _fetch_json("/recentvictims")
        groups = _fetch_json("/groups")
        recent_attacks = _fetch_json("/recentcyberattacks")
    except Exception as exc:  # pragma: no cover - network/runtime dependent
        return {
            "status": "error",
            "message": f"Failed to fetch ransomware.live data: {exc}",
            "provider": "ransomware.live",
            "base_url": settings.ransomware_live_base_url,
        }

    top_groups = _top_groups(recent_victims)

    return {
        "status": "ok",
        "provider": "ransomware.live",
        "base_url": settings.ransomware_live_base_url,
        "info": info,
        "top_groups": top_groups,
        "recent_victims": recent_victims[:12] if isinstance(recent_victims, list) else [],
        "recent_attacks": recent_attacks[:12] if isinstance(recent_attacks, list) else [],
        "group_count": len(groups) if isinstance(groups, list) else 0,
    }


def get_live_group_detail(group_name: str) -> dict:
    if not settings.ransomware_live_enabled:
        return {
            "status": "disabled",
            "message": "Live ransomware group detail is disabled.",
            "provider": "ransomware.live",
        }

    safe_group = parse.quote(group_name.strip().lower())
    try:
        detail = _fetch_json(f"/group/{safe_group}")
        victims = _fetch_json(f"/groupvictims/{safe_group}")
        yara = _fetch_json(f"/yara/{safe_group}")
    except Exception as exc:  # pragma: no cover - network/runtime dependent
        return {
            "status": "error",
            "message": f"Failed to fetch group detail: {exc}",
            "provider": "ransomware.live",
        }

    return {
        "status": "ok",
        "provider": "ransomware.live",
        "group": detail,
        "victims": victims[:25] if isinstance(victims, list) else [],
        "yara": yara,
    }


def _fetch_json(path: str):
    req = request.Request(
        f"{settings.ransomware_live_base_url.rstrip('/')}{path}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with request.urlopen(req, timeout=settings.ransomware_live_timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _top_groups(recent_victims) -> list[dict]:
    if not isinstance(recent_victims, list):
        return []

    counts: dict[str, int] = {}
    for item in recent_victims:
        group = (item.get("group") or "unknown").strip()
        counts[group] = counts.get(group, 0) + 1

    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{"group": group, "count": count} for group, count in ranked[:10]]
