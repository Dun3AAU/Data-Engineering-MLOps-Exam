"""Exploratory Data Analysis (EDA) script for the CVE database."""

from __future__ import annotations

import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.models import CVE, CPEMatch
from sqlalchemy import func, distinct


logger = logging.getLogger(__name__)


DATA_DIR = ROOT / "data"
LOG_DIR = DATA_DIR / "log"
LOG_PATH = LOG_DIR / "explore.log"


def setup_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Rotating file handler
    fh = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Also log to stdout
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


def print_section(title: str) -> None:
    logger.info("\n%s", "=" * 60)
    logger.info("  %s", title)
    logger.info("%s", "=" * 60)


def main() -> None:
    global logger
    logger = setup_logger()
    session = get_session()
    try:
        # Total counts
        print_section("Database Overview")
        total_cves = session.query(func.count(CVE.id)).scalar()
        total_cpe_matches = session.query(func.count(CPEMatch.id)).scalar()
        logger.info("Total CVEs: %s", f"{total_cves:,}")
        logger.info("Total CPE matches: %s", f"{total_cpe_matches:,}")

        # Date ranges
        print_section("Date Range")
        earliest = session.query(func.min(CVE.published_date)).scalar()
        latest_pub = session.query(func.max(CVE.published_date)).scalar()
        latest_mod = session.query(func.max(CVE.last_modified_date)).scalar()
        logger.info("Earliest CVE published: %s", earliest)
        logger.info("Latest CVE published: %s", latest_pub)
        logger.info("Latest CVE modified: %s", latest_mod)

        # Severity distribution
        print_section("Severity Distribution")
        severity_counts = (
            session.query(CVE.severity, func.count(CVE.id))
            .filter(CVE.severity.isnot(None))
            .group_by(CVE.severity)
            .order_by(func.count(CVE.id).desc())
            .all()
        )
        for severity, count in severity_counts:
            logger.info("  %s: %s", f"{severity:12s}", f"{count:6,}")

        # CVSS score distribution
        print_section("CVSS v3 Score Distribution")
        score_ranges = [
            (0.0, 3.9, "0.0-3.9 (Low)"),
            (4.0, 6.9, "4.0-6.9 (Medium)"),
            (7.0, 8.9, "7.0-8.9 (High)"),
            (9.0, 10.0, "9.0-10.0 (Critical)"),
        ]
        for min_score, max_score, label in score_ranges:
            count = (
                session.query(func.count(CVE.id))
                .filter(CVE.cvss_v3_score >= min_score, CVE.cvss_v3_score <= max_score)
                .scalar()
            )
            logger.info("  %s: %s", f"{label:20s}", f"{count:6,}")

        no_score = session.query(func.count(CVE.id)).filter(CVE.cvss_v3_score.is_(None)).scalar()
        logger.info("  %s: %s", f"{'No score':20s}", f"{no_score:6,}")

        # CVEs by publication year
        print_section("CVEs by Publication Year")
        from sqlalchemy import func as sql_func
        from sqlalchemy import cast
        from sqlalchemy.types import String

        year_counts = (
            session.query(
                cast(sql_func.strftime("%Y", CVE.published_date), String).label("year"),
                func.count(CVE.id),
            )
            .filter(CVE.published_date.isnot(None))
            .group_by("year")
            .order_by("year")
            .all()
        )
        for year, count in year_counts:
            if year:
                    logger.info("  %s: %s", year, f"{count:6,}")

        # Top vendors (by CPE match count)
        print_section("Top 10 Vendors by CVE Count (from CPE)")
        vendor_cpes = (
            session.query(CPEMatch.cpe23Uri, func.count(CPEMatch.id))
            .group_by(CPEMatch.cpe23Uri)
            .order_by(func.count(CPEMatch.id).desc())
            .limit(100)
            .all()
        )
        vendors = {}
        for cpe_uri, count in vendor_cpes:
            if not cpe_uri:
                continue
            parts = cpe_uri.split(":")
            if len(parts) >= 4:
                vendor = parts[3]
                if vendor and vendor != "*":
                    vendors[vendor] = vendors.get(vendor, 0) + count

        sorted_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]
        for vendor, count in sorted_vendors:
            logger.info("  %s: %s", f"{vendor:30s}", f"{count:6,}")

        # High-severity CVEs
        print_section("Sample High-Severity CVEs")
        high_severity = (
            session.query(CVE.cve_id, CVE.cvss_v3_score, CVE.severity, CVE.published_date)
            .filter(CVE.severity == "CRITICAL")
            .order_by(CVE.published_date.desc())
            .limit(10)
            .all()
        )
        for cve_id, score, severity, pub_date in high_severity:
            logger.info("  %s (%s) - %s", f"{cve_id:20s}", f"{score:4.1f}", pub_date)

        # Database statistics
        print_section("Data Quality")
        with_description = (
            session.query(func.count(CVE.id)).filter(CVE.description.isnot(None), CVE.description != "").scalar()
        )
        with_cvss = session.query(func.count(CVE.id)).filter(CVE.cvss_v3_score.isnot(None)).scalar()
        with_cpe = (
            session.query(func.count(distinct(CPEMatch.cve_id))).scalar()
        )
        logger.info("CVEs with description: %s", f"{with_description:,} ({100*with_description/total_cves:.1f}%)")
        logger.info("CVEs with CVSS score: %s", f"{with_cvss:,} ({100*with_cvss/total_cves:.1f}%)")
        logger.info("CVEs with CPE matches: %s", f"{with_cpe:,} ({100*with_cpe/total_cves:.1f}%)")

    finally:
        session.close()


if __name__ == "__main__":
    main()
