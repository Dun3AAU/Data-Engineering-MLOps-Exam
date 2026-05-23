#!/usr/bin/env python3
"""Run CVE-to-Infrastructure matching process."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.infrastructure_extractor import InfrastructureExtractor
from backend.API.matcher import CVEInfrastructureMatcher
from sqlalchemy import func
from backend.API.models import CVE, Finding


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def main() -> None:
    """Run the matching process."""
    
    print_section("CVE-Infrastructure Matching Engine")
    
    # Initialize
    session = get_session()
    infra_dir = ROOT / "backend" / "infrastructure"
    
    # Check CVE database status
    print_section("Database Status")
    total_cves = session.query(func.count(CVE.id)).scalar()
    print(f"Total CVEs in database: {total_cves:,}")
    
    if total_cves == 0:
        print("\n⚠️  WARNING: No CVEs in database. Run populate_db.py or update_db.py first.")
        return
    
    # Extract infrastructure
    print_section("Infrastructure Extraction")
    print(f"Loading infrastructure from: {infra_dir}")
    
    extractor = InfrastructureExtractor(infra_dir)
    assets = extractor.extract_all()
    
    print(f"✓ Extracted {len(assets)} assets from infrastructure")
    
    # Print asset breakdown
    asset_types = {}
    for asset in assets:
        if asset.asset_type not in asset_types:
            asset_types[asset.asset_type] = 0
        asset_types[asset.asset_type] += 1
    
    print("\nAsset breakdown:")
    for asset_type, count in sorted(asset_types.items()):
        print(f"  - {asset_type}: {count}")
    
    # Print total CPEs
    total_cpes = sum(len(a.cpes) for a in assets)
    print(f"\nTotal CPEs extracted: {total_cpes}")
    
    # Run matching
    print_section("CVE Matching")
    print("Matching infrastructure CPEs to CVE database...")
    
    matcher = CVEInfrastructureMatcher(session)
    results = matcher.match_all_assets(assets, save_findings=True)
    
    # Print results
    print_section("Matching Results")
    
    print(f"\nTotal matches found: {results['total_matches']}")
    print(f"Assets checked: {results['total_assets_checked']}")
    print(f"Assets with findings: {results['assets_with_findings']}")
    
    if results['findings_by_severity']:
        print("\nFindings by severity:")
        for severity, count in sorted(
            results['findings_by_severity'].items(),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}.get(x[0], 5)
        ):
            print(f"  - {severity.capitalize()}: {count}")
    
    if results['findings_by_criticality']:
        print("\nAssets by criticality:")
        for criticality, count in sorted(results['findings_by_criticality'].items()):
            print(f"  - {criticality.capitalize()}: {count}")
    
    # Show top matches by severity
    if results['matches']:
        print_section("High Priority Findings")
        
        critical_matches = [m for m in results['matches'] if m.severity == "CRITICAL"]
        high_matches = [m for m in results['matches'] if m.severity == "HIGH"]
        
        if critical_matches:
            print(f"\n🔴 CRITICAL Vulnerabilities ({len(critical_matches)}):")
            for match in critical_matches[:5]:  # Show top 5
                print(
                    f"  • {match.cve_id}: {match.asset_id} "
                    f"({match.asset_type}, criticality: {match.criticality})"
                )
                if match.cvss_v3_score:
                    print(f"    CVSS Score: {match.cvss_v3_score}")
                print(f"    {match.match_reason}")
            if len(critical_matches) > 5:
                print(f"  ... and {len(critical_matches) - 5} more")
        
        if high_matches:
            print(f"\n🟠 HIGH Vulnerabilities ({len(high_matches)}):")
            for match in high_matches[:5]:  # Show top 5
                print(
                    f"  • {match.cve_id}: {match.asset_id} "
                    f"({match.asset_type}, criticality: {match.criticality})"
                )
                if match.cvss_v3_score:
                    print(f"    CVSS Score: {match.cvss_v3_score}")
                print(f"    {match.match_reason}")
            if len(high_matches) > 5:
                print(f"  ... and {len(high_matches) - 5} more")
    
    # Internet-exposed summary
    print_section("Internet-Exposed Assets with Vulnerabilities")
    
    exposed_matches = [m for m in results['matches'] if m.internet_exposed]
    if exposed_matches:
        print(f"\n⚠️  Found {len(exposed_matches)} vulnerabilities in internet-exposed assets:")
        exposed_by_asset = {}
        for match in exposed_matches:
            if match.asset_id not in exposed_by_asset:
                exposed_by_asset[match.asset_id] = []
            exposed_by_asset[match.asset_id].append(match)
        
        for asset_id, matches_list in sorted(exposed_by_asset.items()):
            print(f"\n  {asset_id}: {len(matches_list)} vulnerabilities")
            severities = {}
            for m in matches_list:
                sev = m.severity or "Unknown"
                severities[sev] = severities.get(sev, 0) + 1
            for sev, count in sorted(severities.items()):
                print(f"    - {sev}: {count}")
    else:
        print("\n✓ No vulnerabilities found in internet-exposed assets")
    
    print_section("Complete")
    print("\n✓ Matching process complete. Findings saved to database.\n")


if __name__ == "__main__":
    main()
