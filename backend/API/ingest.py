import json
from datetime import datetime, timezone
from typing import Iterable, Optional

import httpx
from sqlalchemy.orm import Session

from .db import engine
from .models import Base, CPEMatch, CVE

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = None
DEFAULT_SLEEP_SECONDS = 6.0


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def _format_nvd_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _call_nvd(params: dict) -> dict:
    with httpx.Client(timeout=120.0) as client:
        response = client.get(NVD_BASE, params=params)
        response.raise_for_status()
        return response.json()


def fetch_cves(
    *,
    start_index: int = 0,
    results_per_page: Optional[int] = DEFAULT_RESULTS_PER_PAGE,
    last_mod_start: Optional[datetime] = None,
    last_mod_end: Optional[datetime] = None,
    pub_start: Optional[datetime] = None,
    pub_end: Optional[datetime] = None,
) -> dict:
    params = {"startIndex": start_index}
    if results_per_page is not None:
        params["resultsPerPage"] = results_per_page
    if last_mod_start is not None:
        params["lastModStartDate"] = _format_nvd_datetime(last_mod_start)
    if last_mod_end is not None:
        params["lastModEndDate"] = _format_nvd_datetime(last_mod_end)
    if pub_start is not None:
        params["pubStartDate"] = _format_nvd_datetime(pub_start)
    if pub_end is not None:
        params["pubEndDate"] = _format_nvd_datetime(pub_end)
    return _call_nvd(params)


def iter_cves(
    *,
    start_index: int = 0,
    last_mod_start: Optional[datetime] = None,
    last_mod_end: Optional[datetime] = None,
    pub_start: Optional[datetime] = None,
    pub_end: Optional[datetime] = None,
    sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
) -> Iterable[dict]:
    idx = start_index
    while True:
        payload = fetch_cves(
            start_index=idx,
            last_mod_start=last_mod_start,
            last_mod_end=last_mod_end,
            pub_start=pub_start,
            pub_end=pub_end,
        )
        vulnerabilities = payload.get("vulnerabilities", [])
        total_results = payload.get("totalResults", 0)
        if not vulnerabilities:
            break

        yield {
            "payload": payload,
            "vulnerabilities": vulnerabilities,
            "start_index": idx,
            "total_results": total_results,
        }

        idx += len(vulnerabilities)
        if idx >= total_results:
            break
        if sleep_seconds > 0:
            import time

            time.sleep(sleep_seconds)


def _extract_cve(vulnerability: dict) -> dict:
    cve = vulnerability.get("cve", vulnerability)
    cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")

    descriptions = cve.get("descriptions") or cve.get("description", {}).get("description_data", [])
    description = ""
    for entry in descriptions or []:
        if entry.get("lang") in (None, "en") and entry.get("value"):
            description = entry["value"]
            break
    if not description and descriptions:
        description = next((entry.get("value") for entry in descriptions if entry.get("value")), "")

    published = cve.get("published") or vulnerability.get("publishedDate")
    modified = cve.get("lastModified") or vulnerability.get("lastModifiedDate")

    def parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None

    metrics = cve.get("metrics", {}) or vulnerability.get("impact", {})
    cvss_score = None
    cvss_vector = None
    severity = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key) or []
        if not metric_list:
            continue
        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {}) or {}
        cvss_score = cvss_data.get("baseScore") or metric.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        severity = metric.get("baseSeverity") or metric.get("severity")
        break

    configurations = cve.get("configurations") or vulnerability.get("configurations") or []

    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": parse_dt(published),
        "last_modified_date": parse_dt(modified),
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "severity": severity,
        "raw": json.dumps(vulnerability, ensure_ascii=False),
        "configurations": configurations,
    }


def _iter_nodes(configurations: object) -> Iterable[dict]:
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes", [])
        for node in nodes:
            yield node
        return

    if isinstance(configurations, list):
        for config in configurations:
            for node in config.get("nodes", []) if isinstance(config, dict) else []:
                yield node


def _iter_cpe_matches(node: dict) -> Iterable[dict]:
    for match in node.get("cpeMatch", []) or node.get("cpe_match", []):
        yield match

    for child in node.get("children", []) or []:
        yield from _iter_cpe_matches(child)


def upsert_cve(session: Session, vulnerability: dict) -> bool:
    """Upsert a CVE. Returns True if a new CVE row was created, False if updated or skipped."""
    record = _extract_cve(vulnerability)
    cve_id = record["cve_id"]
    if not cve_id:
        return False

    existing = session.query(CVE).filter(CVE.cve_id == cve_id).one_or_none()
    created = False
    if existing is None:
        existing = CVE(cve_id=cve_id)
        session.add(existing)
        session.flush()
        created = True

    existing.published_date = record["published_date"]
    existing.last_modified_date = record["last_modified_date"]
    existing.description = record["description"]
    existing.cvss_v3_score = record["cvss_v3_score"]
    existing.cvss_v3_vector = record["cvss_v3_vector"]
    existing.severity = record["severity"]
    existing.raw = record["raw"]

    session.query(CPEMatch).filter(CPEMatch.cve_id == existing.id).delete()

    for node in _iter_nodes(record["configurations"]):
        for match in _iter_cpe_matches(node):
            cpe_uri = match.get("criteria") or match.get("cpe23Uri")
            if not cpe_uri:
                continue
            session.add(
                CPEMatch(
                    cve_id=existing.id,
                    cpe23Uri=cpe_uri,
                    versionStartIncluding=match.get("versionStartIncluding"),
                    versionEndIncluding=match.get("versionEndIncluding"),
                    raw=json.dumps(match, ensure_ascii=False),
                )
            )

    return created

