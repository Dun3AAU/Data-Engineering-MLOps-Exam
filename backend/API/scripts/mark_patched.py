#!/usr/bin/env python3
"""
Remediation tracking script - Update finding patch status and notes.

Examples:
    # Mark a CVE as patched on specific asset
    python mark_patched.py --cve CVE-2024-1234 --asset HQ-BILL01 \\
        --version "2402" --status patched \\
        --notes "Applied Windows Update KB5038304"
    
    # Mark as mitigated (workaround applied)
    python mark_patched.py --cve CVE-2025-5678 --asset DC01 \\
        --status mitigated \\
        --notes "Applied firewall rule to restrict access"
    
    # Mark as accepted (known risk)
    python mark_patched.py --cve CVE-2026-1234 --asset MAIL01 \\
        --status accepted \\
        --notes "Accepted risk - vendor says patch breaks compatibility"
    
    # View remediation status for an asset
    python mark_patched.py --asset HQ-BILL01 --show-status
    
    # View remediation status for a CVE
    python mark_patched.py --cve CVE-2024-1234 --show-status
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
import argparse
from datetime import datetime

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.models import Finding


def update_remediation(
    cve_id: str,
    asset_id: str,
    status: str,
    version: str | None = None,
    notes: str | None = None
) -> bool:
    """
    Update remediation status for a finding.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        asset_id: Asset hostname
        status: One of "open", "patched", "mitigated", "accepted"
        version: Patched version (e.g., "2402")
        notes: Remediation notes
    
    Returns:
        True if updated, False if finding not found
    """
    session = get_session()
    
    # Find finding by CVE and asset
    findings = session.query(Finding).filter(
        Finding.matched_asset == asset_id
    ).all()
    
    updated = False
    for finding in findings:
        # Match by CVE ID in the database record
        # We need to check the CVE table to get the CVE ID string
        from backend.API.models import CVE
        cve_obj = session.query(CVE).filter(CVE.id == finding.cve_id).first()
        
        if cve_obj and cve_obj.cve_id == cve_id:
            finding.remediation_status = status
            if version:
                finding.patched_version = version
            if notes:
                finding.remediation_notes = notes
            if status == "patched" and version:
                finding.patched_at = datetime.utcnow()
            
            session.commit()
            updated = True
            logging.getLogger(__name__).info("✓ Updated %s on %s: %s", cve_id, asset_id, status)
            if notes:
                logging.getLogger(__name__).info("  Notes: %s", notes)
            break
    
    if not updated:
        logging.getLogger(__name__).error("✗ Finding not found: %s on %s", cve_id, asset_id)
    
    return updated


def show_remediation_status(
    cve_id: str | None = None,
    asset_id: str | None = None
) -> None:
    """Display remediation status for findings."""
    session = get_session()
    
    # Build query
    query = session.query(Finding)
    
    if cve_id:
        from backend.API.models import CVE
        cve_obj = session.query(CVE).filter(CVE.cve_id == cve_id).first()
        if cve_obj:
            query = query.filter(Finding.cve_id == cve_obj.id)
        else:
            logging.getLogger(__name__).error("✗ CVE not found: %s", cve_id)
            return
    
    if asset_id:
        query = query.filter(Finding.matched_asset == asset_id)
    
    findings = query.all()
    
    if not findings:
        logging.getLogger(__name__).info("No findings found.")
        return
    
    logger = logging.getLogger(__name__)
    logger.info("\n%s", "=" * 80)
    logger.info("  Remediation Status")
    logger.info("%s\n", "=" * 80)
    
    # Group by asset/CVE
    from collections import defaultdict
    by_asset = defaultdict(list)
    
    for finding in findings:
        from backend.API.models import CVE
        cve = session.query(CVE).filter(CVE.id == finding.cve_id).first()
        cve_id_str = cve.cve_id if cve else f"CVE-ID-{finding.cve_id}"
        
        by_asset[finding.matched_asset].append({
            'cve_id': cve_id_str,
            'status': finding.remediation_status or 'open',
            'patched_version': finding.patched_version,
            'patched_at': finding.patched_at,
            'notes': finding.remediation_notes,
        })
    
    # Display
    for asset in sorted(by_asset.keys()):
        logger.info("%s:", asset)
        for item in by_asset[asset]:
            status_icon = {
                'open': '○',
                'patched': '✓',
                'mitigated': '⚠',
                'accepted': '∼',
            }.get(item['status'], '?')
            
            logger.info("  %s %s: %s", status_icon, item['cve_id'], item['status'])
            
            if item['patched_version']:
                logger.info("     Patched to: %s", item['patched_version'])
            
            if item['patched_at']:
                logger.info("     Patched at: %s", item['patched_at'])
            
            if item['notes']:
                logger.info("     Notes: %s", item['notes'])
        
        logger.info("")


def main():
    parser = argparse.ArgumentParser(
        description="Update remediation status and tracking for CVE findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Query options
    parser.add_argument('--cve', type=str, help='CVE ID (e.g., CVE-2024-1234)')
    parser.add_argument('--asset', type=str, help='Asset hostname (e.g., HQ-BILL01)')
    
    # Action options
    parser.add_argument(
        '--status',
        type=str,
        choices=['open', 'patched', 'mitigated', 'accepted'],
        help='Remediation status'
    )
    parser.add_argument('--version', type=str, help='Patched version')
    parser.add_argument('--notes', type=str, help='Remediation notes')
    parser.add_argument(
        '--show-status',
        action='store_true',
        help='Show remediation status (use with --cve or --asset)'
    )
    
    args = parser.parse_args()
    
    # Show status
    if args.show_status:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        show_remediation_status(cve_id=args.cve, asset_id=args.asset)
        return
    
    # Update status
    if args.cve and args.asset and args.status:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        update_remediation(
            cve_id=args.cve,
            asset_id=args.asset,
            status=args.status,
            version=args.version,
            notes=args.notes
        )
    else:
        # If no action specified, show help
        if not args.show_status:
            parser.print_help()


if __name__ == "__main__":
    main()
