"""Fetchers for CISA data: Known Exploited Vulnerabilities and Alerts."""
import requests
import feedparser
from datetime import datetime, timedelta
from config import CISA_KEV_URL, CISA_ALERTS_RSS


def get_recent_kev_entries(days: int = 7, limit: int = 10) -> list[dict]:
    """
    Fetch recently added entries from CISA's Known Exploited Vulnerabilities catalog.
    Returns the most recently added vulnerabilities (sorted by dateAdded desc).
    """
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return [{"error": str(e)}]

    vulnerabilities = data.get("vulnerabilities", [])

    # Filter to entries added within the last `days` days
    cutoff = datetime.now() - timedelta(days=days)
    recent = []
    for v in vulnerabilities:
        date_str = v.get("dateAdded", "")
        try:
            added = datetime.strptime(date_str, "%Y-%m-%d")
            if added >= cutoff:
                recent.append(v)
        except ValueError:
            continue

    # Sort by dateAdded descending, return top `limit`
    recent.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return recent[:limit] if recent else vulnerabilities[:limit]


def get_cisa_alerts(limit: int = 5) -> list[dict]:
    """
    Fetch recent CISA cybersecurity alerts from the RSS feed.
    Returns a list of dicts with title, summary, link, published.
    """
    try:
        feed = feedparser.parse(CISA_ALERTS_RSS)
    except Exception as e:
        return [{"error": str(e)}]

    alerts = []
    for entry in feed.entries[:limit]:
        alerts.append({
            "title": entry.get("title", "No title"),
            "summary": entry.get("summary", "No summary available")[:800],
            "link": entry.get("link", ""),
            "published": entry.get("published", "Unknown date"),
        })
    return alerts


def get_all_kev_stats() -> dict:
    """Return high-level statistics and the full sorted catalog from CISA KEV."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return {"error": str(e)}

    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)

    vendors: dict[str, int] = {}
    for v in vulns:
        vendor = v.get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_entries": len(vulns),
        "catalog_version": data.get("catalogVersion", "N/A"),
        "date_released": data.get("dateReleased", "N/A"),
        "top_vendors": top_vendors,
        "vulnerabilities": vulns,
    }
