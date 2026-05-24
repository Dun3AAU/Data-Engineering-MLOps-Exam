#!/usr/bin/env python3
"""Run CVE-to-Infrastructure matching process."""

from __future__ import annotations

import sys
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.infrastructure_extractor import InfrastructureExtractor
from backend.API.matcher import CVEInfrastructureMatcher
from sqlalchemy import func
from backend.API.models import CVE


logger = logging.getLogger(__name__)


def print_section(title: str) -> None:
    """Log a formatted section header."""
    logger.info("\n%s", "=" * 70)
    logger.info("  %s", title)
    logger.info("%s", "=" * 70)


def main() -> None:
    """Run the matching process."""
    
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    print_section("CVE-Infrastructure Matching Engine")
    
    # Initialize
    session = get_session()
    infra_dir = ROOT / "backend" / "infrastructure"
    
    # Check CVE database status
    print_section("Database Status")
    total_cves = session.query(func.count(CVE.id)).scalar()
    logger.info("Total CVEs in database: %s", f"{total_cves:,}")
    
    if total_cves == 0:
        logger.warning("⚠️  WARNING: No CVEs in database. Run populate_db.py or update_db.py first.")
        return
    
    # Extract infrastructure
    print_section("Infrastructure Extraction")
    logger.info("Loading infrastructure from: %s", infra_dir)
    
    extractor = InfrastructureExtractor(infra_dir)
    assets = extractor.extract_all()
    
    logger.info("✓ Extracted %d assets from infrastructure", len(assets))
    
    # Print asset breakdown
    asset_types = {}
    for asset in assets:
        if asset.asset_type not in asset_types:
            asset_types[asset.asset_type] = 0
        asset_types[asset.asset_type] += 1
    
    logger.info("\nAsset breakdown:")
    for asset_type, count in sorted(asset_types.items()):
        logger.info("  - %s: %d", asset_type, count)
    
    # Print total CPEs
    total_cpes = sum(len(a.cpes) for a in assets)
    logger.info("\nTotal CPEs extracted: %d", total_cpes)
    
    # Run matching
    print_section("CVE Matching")
    logger.info("Matching infrastructure CPEs to CVE database...")
    
    matcher = CVEInfrastructureMatcher(session)
    results = matcher.match_all_assets(assets, save_findings=True)
    
    # Print results
    print_section("Matching Results")

    logger.info("\nTotal matches found: %s", results["total_matches"])
    logger.info("Assets checked: %s", results["total_assets_checked"])
    logger.info("Assets with findings: %s", results["assets_with_findings"])
    
    if results['findings_by_severity']:
        logger.info("\nFindings by severity:")
        for severity, count in sorted(
            results["findings_by_severity"].items(),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}.get(x[0], 5)
        ):
            logger.info("  - %s: %s", severity.capitalize(), count)
    
    if results['findings_by_criticality']:
        logger.info("\nAssets by criticality:")
        for criticality, count in sorted(results["findings_by_criticality"].items()):
            logger.info("  - %s: %s", criticality.capitalize(), count)
    
    # Show top matches by severity
    if results['matches']:
        print_section("High Priority Findings")
        
        critical_matches = [m for m in results['matches'] if m.severity == "CRITICAL"]
        high_matches = [m for m in results['matches'] if m.severity == "HIGH"]
        
        if critical_matches:
            logger.info("\n🔴 CRITICAL Vulnerabilities (%d):", len(critical_matches))
            for match in critical_matches[:5]:  # Show top 5
                logger.info("  • %s: %s (%s, criticality: %s)", match.cve_id, match.asset_id, match.asset_type, match.criticality)
                if match.cvss_v3_score:
                    logger.info("    CVSS Score: %s", match.cvss_v3_score)
                logger.info("    %s", match.match_reason)
            if len(critical_matches) > 5:
                logger.info("  ... and %d more", len(critical_matches) - 5)
        
        if high_matches:
            logger.info("\n🟠 HIGH Vulnerabilities (%d):", len(high_matches))
            for match in high_matches[:5]:  # Show top 5
                logger.info("  • %s: %s (%s, criticality: %s)", match.cve_id, match.asset_id, match.asset_type, match.criticality)
                if match.cvss_v3_score:
                    logger.info("    CVSS Score: %s", match.cvss_v3_score)
                logger.info("    %s", match.match_reason)
            if len(high_matches) > 5:
                logger.info("  ... and %d more", len(high_matches) - 5)
    
    # Internet-exposed summary
    print_section("Internet-Exposed Assets with Vulnerabilities")
    
    exposed_matches = [m for m in results['matches'] if m.internet_exposed]
    if exposed_matches:
        logger.warning("\n⚠️  Found %d vulnerabilities in internet-exposed assets:", len(exposed_matches))
        exposed_by_asset = {}
        for match in exposed_matches:
            if match.asset_id not in exposed_by_asset:
                exposed_by_asset[match.asset_id] = []
            exposed_by_asset[match.asset_id].append(match)
        
        for asset_id, matches_list in sorted(exposed_by_asset.items()):
            logger.info("\n  %s: %d vulnerabilities", asset_id, len(matches_list))
            severities = {}
            for m in matches_list:
                sev = m.severity or "Unknown"
                severities[sev] = severities.get(sev, 0) + 1
            for sev, count in sorted(severities.items()):
                logger.info("    - %s: %d", sev, count)
    else:
        logger.info("\n✓ No vulnerabilities found in internet-exposed assets")
    
    print_section("Complete")
    logger.info("\n✓ Matching process complete. Findings saved to database.\n")


if __name__ == "__main__":
    main()
