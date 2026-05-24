#!/usr/bin/env python3
"""
Example: Query findings for LLM-based reasoning layer.

This demonstrates how to extract findings from the database
for further processing by the LLM reasoning engine.
"""

from __future__ import annotations

import sys
from pathlib import Path
import json
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.models import Finding


def print_section(title: str) -> None:
    """Print formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def query_high_priority_findings(session) -> list:
    """Get findings that need immediate attention."""
    findings = session.query(Finding).all()
    
    high_priority = []
    for finding in findings:
        details = json.loads(finding.match_details)
        
        # Mark as high priority if:
        # 1. Severity is CRITICAL or HIGH
        # 2. AND asset is internet-exposed or critical
        if details.get('severity') in ['CRITICAL', 'HIGH']:
            if details.get('internet_exposed') or details.get('criticality') == 'critical':
                high_priority.append({
                    'cve_id': finding.cve_id,
                    'asset_id': finding.matched_asset,
                    'severity': details.get('severity'),
                    'criticality': details.get('criticality'),
                    'internet_exposed': details.get('internet_exposed'),
                    'cvss_score': details.get('cvss_v3_score'),
                    'confidence': details.get('match_confidence'),
                    'reason': details.get('match_reason'),
                })
    
    return sorted(high_priority, key=lambda x: (
        -2 if x['severity'] == 'CRITICAL' else -1 if x['severity'] == 'HIGH' else 0,
        -float(x['cvss_score'] or 0),
        -float(x['confidence'] or 0)
    ))


def query_findings_by_asset(session) -> dict:
    """Group findings by asset for asset-focused reasoning."""
    findings = session.query(Finding).all()
    
    by_asset = defaultdict(lambda: {
        'total': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'internet_exposed': False,
        'criticality': 'low',
        'vulnerabilities': []
    })
    
    for finding in findings:
        details = json.loads(finding.match_details)
        asset_id = finding.matched_asset
        
        asset_info = by_asset[asset_id]
        asset_info['total'] += 1
        asset_info['internet_exposed'] = asset_info['internet_exposed'] or details.get('internet_exposed', False)
        
        # Track highest criticality
        criticality_map = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}
        if criticality_map.get(details.get('criticality', 'low'), 0) > criticality_map.get(asset_info['criticality'], 0):
            asset_info['criticality'] = details.get('criticality', 'low')
        
        # Count by severity
        severity = details.get('severity', 'Unknown').lower()
        if severity in asset_info:
            asset_info[severity] += 1
        
        # Add vulnerability details
        asset_info['vulnerabilities'].append({
            'cve_id': finding.cve_id,
            'severity': details.get('severity'),
            'cvss_score': details.get('cvss_v3_score'),
            'reason': details.get('match_reason'),
            'remediation_status': finding.remediation_status or 'open',
            'patched_version': finding.patched_version,
            'remediation_notes': finding.remediation_notes,
        })
    
    return dict(by_asset)


def query_findings_by_severity_and_criticality(session) -> dict:
    """Create impact matrix: asset criticality vs vulnerability severity."""
    findings = session.query(Finding).all()
    
    matrix = defaultdict(int)
    
    for finding in findings:
        details = json.loads(finding.match_details)
        severity = details.get('severity', 'Unknown')
        criticality = details.get('criticality', 'unknown')
        
        matrix[f"{criticality}_{severity}"] += 1
    
    return dict(matrix)


def generate_llm_context(session) -> str:
    """Generate context for LLM reasoning layer."""
    findings = session.query(Finding).all()
    
    if not findings:
        return "No findings available."
    
    # Aggregate statistics
    total = len(findings)
    by_severity = defaultdict(int)
    by_criticality = defaultdict(int)
    by_asset = defaultdict(list)
    internet_exposed_count = 0
    
    for finding in findings:
        details = json.loads(finding.match_details)
        by_severity[details.get('severity', 'Unknown')] += 1
        by_criticality[details.get('criticality', 'unknown')] += 1
        by_asset[finding.matched_asset].append(details.get('severity'))
        if details.get('internet_exposed'):
            internet_exposed_count += 1
    
    # Build context
    context = f"""
# CVE Threat Assessment Report

## Summary Statistics
- Total vulnerabilities found: {total}
- Assets with vulnerabilities: {len(by_asset)}
- Internet-exposed vulnerabilities: {internet_exposed_count}

## Severity Distribution
"""
    for severity, count in sorted(by_severity.items(), key=lambda x: -x[1]):
        context += f"- {severity}: {count}\n"
    
    context += "\n## Asset Criticality Distribution\n"
    for criticality, count in sorted(by_criticality.items(), key=lambda x: -x[1]):
        context += f"- {criticality.capitalize()}: {count}\n"
    
    context += "\n## Most Affected Assets\n"
    for asset, vulns in sorted(by_asset.items(), key=lambda x: -len(x[1]))[:5]:
        severity_breakdown = defaultdict(int)
        for sev in vulns:
            severity_breakdown[sev] += 1
        sev_str = ", ".join(f"{s}: {c}" for s, c in sorted(severity_breakdown.items()))
        context += f"- {asset}: {len(vulns)} vulnerabilities ({sev_str})\n"
    
    return context


def main() -> None:
    """Run example queries."""
    session = get_session()
    
    print_section("High Priority Findings for LLM")
    
    high_priority = query_high_priority_findings(session)
    
    if high_priority:
        print("Findings requiring immediate attention:\n")
        for i, finding in enumerate(high_priority[:10], 1):
            print(f"{i}. {finding['cve_id']}")
            print(f"   Asset: {finding['asset_id']} (criticality: {finding['criticality']})")
            print(f"   Severity: {finding['severity']} | CVSS: {finding['cvss_score']}")
            print(f"   Internet Exposed: {'YES ⚠️' if finding['internet_exposed'] else 'No'}")
            print(f"   Confidence: {finding['confidence']:.1%}")
            print()
        
        if len(high_priority) > 10:
            print(f"... and {len(high_priority) - 10} more high-priority findings\n")
    else:
        print("No high-priority findings.\n")
    
    # Asset breakdown
    print_section("Findings Grouped by Asset")
    
    by_asset = query_findings_by_asset(session)
    
    for asset_id in sorted(by_asset.keys()):
        info = by_asset[asset_id]
        exposed_marker = "🌐 EXPOSED" if info['internet_exposed'] else ""
        print(f"{asset_id} ({info['criticality'].upper()}) {exposed_marker}")
        print(f"  Total: {info['total']} | Critical: {info['critical']} | High: {info['high']} | Medium: {info['medium']}")
    
    # Impact matrix
    print_section("Impact Matrix: Criticality vs Severity")
    
    matrix = query_findings_by_severity_and_criticality(session)
    
    print("Asset Criticality vs Vulnerability Severity:")
    print()
    
    # Organize and display
    criticalities = ['critical', 'high', 'medium', 'low']
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'Unknown']
    
    # Header
    print(f"{'Criticality':<15} {'CRITICAL':>10} {'HIGH':>10} {'MEDIUM':>10} {'LOW':>10} {'Unknown':>10}")
    print("-" * 65)
    
    for crit in criticalities:
        counts = []
        for sev in severities:
            key = f"{crit}_{sev}"
            counts.append(matrix.get(key, 0))
        print(f"{crit:<15} {counts[0]:>10} {counts[1]:>10} {counts[2]:>10} {counts[3]:>10} {counts[4]:>10}")
    
    # LLM context
    print_section("LLM Reasoning Context")
    
    llm_context = generate_llm_context(session)
    print(llm_context)
    
    print_section("Example: Extracting for LLM")
    
    print("""
To feed findings to the LLM reasoning layer:

```python
import json
from backend.API.db import get_session
from backend.API.models import Finding

session = get_session()
findings = session.query(Finding).all()

# Prepare for LLM
findings_for_llm = []
for finding in findings:
    details = json.loads(finding.match_details)
    
    # Only process high-impact items
    if details['severity'] in ['CRITICAL', 'HIGH']:
        findings_for_llm.append({
            'cve': finding.cve_id,
            'asset': finding.matched_asset,
            'severity': details['severity'],
            'asset_criticality': details['criticality'],
            'exposed': details['internet_exposed'],
            'cvss': details['cvss_v3_score'],
        })

# Send to LLM for reasoning
llm_prompt = f"Analyze these security findings and recommend actions: {json.dumps(findings_for_llm)}"
```
    """)


if __name__ == "__main__":
    main()
