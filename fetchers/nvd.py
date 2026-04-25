"""Fetchers for NVD (NIST National Vulnerability Database) CVE data."""
import requests
from datetime import datetime, timedelta
from config import NVD_CVE_URL


def get_recent_critical_cves(days: int = 7, limit: int = 10) -> list[dict]:
    """
    Fetch recent HIGH and CRITICAL CVEs from the NVD API.
    Uses the public NVD 2.0 API (no auth required, rate-limited).
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": limit,
        "startIndex": 0,
    }

    try:
        response = requests.get(NVD_CVE_URL, params=params, timeout=20)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return [{"error": str(e), "source": "NVD API"}]

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = "UNKNOWN"

        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity = cvss_data.get("baseSeverity", metric_list[0].get("baseSeverity", "UNKNOWN"))
                break

        # Extract CWEs
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("value", ""))

        # Extract affected products
        configurations = cve.get("configurations", [])
        affected_products = []
        for config in configurations[:3]:
            for node in config.get("nodes", [])[:2]:
                for cpe_match in node.get("cpeMatch", [])[:2]:
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            affected_products.append(f"{parts[3]} {parts[4]}")

        cves.append({
            "id": cve_id,
            "description": description[:600],
            "published": cve.get("published", "Unknown"),
            "last_modified": cve.get("lastModified", "Unknown"),
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "cwes": cwes[:3],
            "affected_products": list(set(affected_products))[:5],
            "references": [
                r.get("url", "")
                for r in cve.get("references", [])[:3]
            ],
        })

    return cves


def get_cve_by_id(cve_id: str) -> dict | None:
    """Fetch detailed information about a specific CVE by its ID."""
    params = {"cveId": cve_id.upper().strip()}
    try:
        response = requests.get(NVD_CVE_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return {"error": str(e), "cve_id": cve_id}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available"
    )

    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    severity = "UNKNOWN"

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", metric_list[0].get("baseSeverity", "UNKNOWN"))
            break

    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc.get("value", ""))

    return {
        "id": cve.get("id", cve_id),
        "description": description,
        "published": cve.get("published", "Unknown"),
        "last_modified": cve.get("lastModified", "Unknown"),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwes": cwes,
        "references": [r.get("url", "") for r in cve.get("references", [])[:5]],
        "configurations": cve.get("configurations", []),
    }
