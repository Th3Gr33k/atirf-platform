from __future__ import annotations

import json
from pathlib import Path
from urllib import error, request
import xml.etree.ElementTree as ET

from app.config import settings
from app.models.entities import NewsSource


INTEL_DIR = Path(__file__).resolve().parents[3] / "data" / "intel"


def get_kev_overview() -> dict:
    if not settings.kev_enabled:
        return {
            "status": "disabled",
            "provider": "cisa-kev",
            "message": "CISA KEV feed is disabled.",
        }

    try:
        payload = _fetch_json(settings.kev_url, settings.kev_timeout_seconds)
    except Exception as exc:  # pragma: no cover
        return {
            "status": "error",
            "provider": "cisa-kev",
            "message": f"Failed to fetch KEV feed: {exc}",
        }

    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    ransomware_used = [item for item in vulnerabilities if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"]

    return {
        "status": "ok",
        "provider": "cisa-kev",
        "title": payload.get("title"),
        "catalog_version": payload.get("catalogVersion"),
        "count": len(vulnerabilities),
        "known_ransomware_count": len(ransomware_used),
        "recent_entries": vulnerabilities[:12],
    }


def get_cyber_news_overview(db=None) -> dict:
    if not settings.cyber_news_enabled:
        return {
            "status": "disabled",
            "provider": "cyber-news",
            "message": "Cybersecurity news feeds are disabled.",
            "feeds": [],
        }

    sources = _load_news_sources(db)
    results = []

    for source in sources:
        try:
            items = _fetch_rss(source["url"], settings.cyber_news_timeout_seconds)
            results.append(
                {
                    "name": source["name"],
                    "url": source["url"],
                    "trust_level": source.get("trust_level", "community"),
                    "status": "ok",
                    "items": items[:8],
                }
            )
        except Exception as exc:  # pragma: no cover
            results.append(
                {
                    "name": source["name"],
                    "url": source["url"],
                    "trust_level": source.get("trust_level", "community"),
                    "status": "error",
                    "message": str(exc),
                    "items": [],
                }
            )

    top_items = []
    seen = set()
    for feed in results:
        for item in feed["items"]:
            key = (item.get("title", "").strip().lower(), item.get("link", "").strip().lower())
            if key in seen:
                continue
            seen.add(key)
            top_items.append({**item, "source": feed["name"], "trust_level": feed.get("trust_level", "community")})

    return {
        "status": "ok" if any(feed["status"] == "ok" for feed in results) else "error",
        "provider": "cyber-news",
        "feeds": results,
        "top_items": top_items[:12],
    }


def ensure_default_news_sources(db) -> int:
    if db.query(NewsSource).count():
        return 0

    sources = json.loads((INTEL_DIR / "news_sources.json").read_text(encoding="utf-8"))
    for source in sources:
        db.add(
            NewsSource(
                name=source["name"],
                url=source["url"],
                trust_level=source.get("trust_level", "community"),
                enabled=source.get("enabled", True),
            )
        )
    db.commit()
    return len(sources)


def _load_news_sources(db) -> list[dict]:
    if db is not None:
        records = db.query(NewsSource).filter(NewsSource.enabled == True).all()  # noqa: E712
        if records:
            return [
                {
                    "name": record.name,
                    "url": record.url,
                    "trust_level": record.trust_level,
                    "enabled": record.enabled,
                }
                for record in records
            ]
    return json.loads((INTEL_DIR / "news_sources.json").read_text(encoding="utf-8"))


def _fetch_json(url: str, timeout: int):
    req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _fetch_rss(url: str, timeout: int) -> list[dict]:
    req = request.Request(url, headers={"Accept": "application/rss+xml, application/xml, text/xml"}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc

    root = ET.fromstring(raw)
    items = []

    if root.tag.endswith("rss") or root.find("channel") is not None:
        channel = root.find("channel")
        if channel is not None:
            for item in channel.findall("item"):
                items.append(
                    {
                        "title": _text(item.find("title")),
                        "link": _text(item.find("link")),
                        "published": _text(item.find("pubDate")),
                    }
                )
        return items

    entries = root.findall("{http://www.w3.org/2005/Atom}entry")
    for entry in entries:
        link = entry.find("{http://www.w3.org/2005/Atom}link")
        items.append(
            {
                "title": _text(entry.find("{http://www.w3.org/2005/Atom}title")),
                "link": link.attrib.get("href") if link is not None else "",
                "published": _text(entry.find("{http://www.w3.org/2005/Atom}updated")),
            }
        )
    return items


def _text(element) -> str:
    return (element.text or "").strip() if element is not None and element.text else ""
