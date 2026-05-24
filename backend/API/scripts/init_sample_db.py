#!/usr/bin/env python3
"""Initialize database with sample CVE data for testing."""

from __future__ import annotations

import sys
from pathlib import Path
import json
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session, engine
from backend.API.models import Base, CVE, CPEMatch, Finding


def init_sample_data() -> None:
    """Initialize database with sample data for testing."""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    session = get_session()
    
    # Clear existing data
    session.query(Finding).delete()
    session.query(CPEMatch).delete()
    session.query(CVE).delete()
    session.commit()
    
    # Add sample CVEs
    cves = [
        CVE(
            cve_id="CVE-2024-1234",
            published_date=datetime.utcnow() - timedelta(days=180),
            last_modified_date=datetime.utcnow(),
            description="Sample vulnerability in Google Chrome",
            cvss_v3_score=7.5,
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            severity="HIGH",
            raw=json.dumps({"sample": True})
        ),
        CVE(
            cve_id="CVE-2024-5678",
            published_date=datetime.utcnow() - timedelta(days=90),
            last_modified_date=datetime.utcnow(),
            description="Sample vulnerability in Microsoft Office",
            cvss_v3_score=8.2,
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            severity="HIGH",
            raw=json.dumps({"sample": True})
        ),
        CVE(
            cve_id="CVE-2024-9999",
            published_date=datetime.utcnow() - timedelta(days=30),
            last_modified_date=datetime.utcnow(),
            description="Sample vulnerability in Fortinet FortiGate",
            cvss_v3_score=9.1,
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="CRITICAL",
            raw=json.dumps({"sample": True})
        ),
    ]
    
    for cve in cves:
        session.add(cve)
    
    session.flush()  # Get IDs assigned
    
    # Add sample CPE matches
    cpe_matches = [
        # Chrome vulnerabilities
        CPEMatch(
            cve_id=cves[0].id,
            cpe23Uri="cpe:2.3:a:google:chrome:124.0.6367.91:*:*:*:*:*:*:*",
            versionStartIncluding="120.0",
            versionEndIncluding="124.0.6367.120",
            raw=json.dumps({"sample": True})
        ),
        # Office vulnerabilities
        CPEMatch(
            cve_id=cves[1].id,
            cpe23Uri="cpe:2.3:a:microsoft:office:2402:*:*:*:*:*:*:*",
            versionStartIncluding="2402",
            versionEndIncluding="2402",
            raw=json.dumps({"sample": True})
        ),
        # FortiGate vulnerabilities
        CPEMatch(
            cve_id=cves[2].id,
            cpe23Uri="cpe:2.3:h:fortinet:fortigate_100e:7.0.12:*:*:*:*:*:*:*",
            versionStartIncluding="7.0.0",
            versionEndIncluding="7.0.12",
            raw=json.dumps({"sample": True})
        ),
    ]
    
    for cpe_match in cpe_matches:
        session.add(cpe_match)
    
    session.commit()
    
    print("✓ Sample CVE database initialized")
    print(f"  - {len(cves)} CVEs")
    print(f"  - {len(cpe_matches)} CPE matches")


if __name__ == "__main__":
    init_sample_data()
