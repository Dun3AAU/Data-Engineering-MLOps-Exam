"""CVE-to-Infrastructure matching engine."""

from typing import Optional
from dataclasses import dataclass
from sqlalchemy.orm import Session

from .models import CVE, CPEMatch, Finding
from .cpe_utils import (
    cpe_components_match,
    version_matches_range,
    parse_cpe_uri,
    normalize_cpe_component,
)
from .infrastructure_extractor import InfrastructureAsset
import json
import datetime


@dataclass
class Match:
    """Result of matching an infrastructure asset to a CVE."""
    cve_id: str
    cve_obj: Optional[CVE]
    asset_id: str
    asset_type: str
    site: str
    role: str
    infra_cpe: str
    cve_cpe: str
    cvss_v3_score: Optional[float]
    severity: Optional[str]
    match_confidence: float  # 0.0 to 1.0
    match_reason: str
    version_vulnerable: bool
    internet_exposed: bool
    criticality: str


class CVEInfrastructureMatcher:
    """Match CVEs to infrastructure assets based on CPE matching."""
    
    def __init__(self, session: Session):
        """Initialize matcher with database session."""
        self.session = session
        self._cve_cache = {}
    
    def match_asset(self, asset: InfrastructureAsset) -> list[Match]:
        """
        Find all CVEs that match an infrastructure asset.
        
        Args:
            asset: Infrastructure asset with CPEs
        
        Returns:
            List of matching CVEs with details
        """
        matches = []
        seen_cve_ids = set()  # Avoid duplicate CVEs
        
        for asset_cpe in asset.cpes:
            # Extract vendor/product from CPE for efficient database queries
            asset_parsed = parse_cpe_uri(asset_cpe)
            if not asset_parsed:
                continue
            
            vendor_normalized = normalize_cpe_component(asset_parsed.vendor)
            product_normalized = normalize_cpe_component(asset_parsed.product)
            
            # Query for matching CPEs in database using LIKE for partial matching
            query = self.session.query(CPEMatch).filter(
                CPEMatch.cpe23Uri.ilike(f"%:{vendor_normalized}:{product_normalized}:%")
            ).limit(1000)
            
            for cpe_match in query:
                # Try to match this asset CPE to the CVE CPE match
                match = self._try_match_cpe(
                    asset=asset,
                    asset_cpe=asset_cpe,
                    cpe_match=cpe_match
                )
                if match and match.cve_id not in seen_cve_ids:
                    matches.append(match)
                    seen_cve_ids.add(match.cve_id)
        
        return matches
    
    def _try_match_cpe(
        self,
        asset: InfrastructureAsset,
        asset_cpe: str,
        cpe_match: CPEMatch
    ) -> Optional[Match]:
        """
        Attempt to match an asset CPE to a CVE CPE match.
        
        Returns None if no match, otherwise returns Match object.
        """
        cve_cpe = cpe_match.cpeUri if hasattr(cpe_match, 'cpeUri') else cpe_match.cpe23Uri
        
        # Quick check: do components match?
        if not cpe_components_match(asset_cpe, cve_cpe):
            return None
        
        # Parse CPEs for version checking
        asset_parsed = parse_cpe_uri(asset_cpe)
        cve_parsed = parse_cpe_uri(cve_cpe)
        
        if not asset_parsed or not cve_parsed:
            return None
        
        # Check version range
        version_vulnerable = True
        if cve_parsed.version != "*" or cpe_match.versionStartIncluding or cpe_match.versionEndIncluding:
            version_vulnerable = version_matches_range(
                asset_parsed.version,
                cpe_match.versionStartIncluding,
                cpe_match.versionEndIncluding
            )
        
        if not version_vulnerable:
            return None
        
        # Get CVE data if not cached
        cve_id = cpe_match.cve_id
        if cve_id not in self._cve_cache:
            cve = self.session.query(CVE).filter(CVE.id == cve_id).first()
            self._cve_cache[cve_id] = cve
        else:
            cve = self._cve_cache[cve_id]
        
        if not cve:
            return None
        
        # Calculate match confidence
        confidence = self._calculate_confidence(
            asset_parsed=asset_parsed,
            cve_parsed=cve_parsed,
            version_vulnerable=version_vulnerable
        )
        
        # Determine match reason
        reason = self._determine_reason(
            asset_parsed=asset_parsed,
            cve_parsed=cve_parsed,
            cpe_match=cpe_match
        )
        
        return Match(
            cve_id=cve.cve_id,
            cve_obj=cve,
            asset_id=asset.asset_id,
            asset_type=asset.asset_type,
            site=asset.site,
            role=asset.role,
            infra_cpe=asset_cpe,
            cve_cpe=cve_cpe,
            cvss_v3_score=cve.cvss_v3_score,
            severity=cve.severity,
            match_confidence=confidence,
            match_reason=reason,
            version_vulnerable=version_vulnerable,
            internet_exposed=asset.internet_exposed,
            criticality=asset.criticality
        )
    
    @staticmethod
    def _calculate_confidence(
        asset_parsed,
        cve_parsed,
        version_vulnerable: bool
    ) -> float:
        """
        Calculate match confidence score (0.0 to 1.0).
        
        Factors:
        - Exact part match: +0.3
        - Exact vendor match: +0.2
        - Exact product match: +0.2
        - Version vulnerable: +0.3
        """
        confidence = 0.0
        
        # Part match (strict)
        if asset_parsed.part == cve_parsed.part:
            confidence += 0.3
        
        # Vendor match
        if asset_parsed.vendor != "*" and cve_parsed.vendor != "*":
            if normalize_cpe_component(asset_parsed.vendor) == normalize_cpe_component(cve_parsed.vendor):
                confidence += 0.2
        
        # Product match
        if asset_parsed.product != "*" and cve_parsed.product != "*":
            if normalize_cpe_component(asset_parsed.product) == normalize_cpe_component(cve_parsed.product):
                confidence += 0.2
        
        # Version vulnerable
        if version_vulnerable:
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    @staticmethod
    def _determine_reason(asset_parsed, cve_parsed, cpe_match) -> str:
        """Generate human-readable reason for match."""
        reasons = []
        
        if asset_parsed.vendor and cve_parsed.vendor:
            reasons.append(f"{normalize_cpe_component(cve_parsed.vendor)}")
        if asset_parsed.product and cve_parsed.product:
            reasons.append(f"{normalize_cpe_component(cve_parsed.product)}")
        
        if cpe_match.versionStartIncluding or cpe_match.versionEndIncluding:
            version_range = []
            if cpe_match.versionStartIncluding:
                version_range.append(f">= {cpe_match.versionStartIncluding}")
            if cpe_match.versionEndIncluding:
                version_range.append(f"<= {cpe_match.versionEndIncluding}")
            reasons.append(f"version {', '.join(version_range)}")
        
        return " - ".join(reasons) if reasons else "CPE match"
    
    def match_all_assets(
        self,
        assets: list[InfrastructureAsset],
        save_findings: bool = True
    ) -> dict:
        """
        Match all infrastructure assets to CVEs.
        
        Args:
            assets: List of infrastructure assets
            save_findings: If True, save findings to database
        
        Returns:
            Dictionary with match statistics and results
        """
        all_matches = []
        findings_by_criticality = {}
        findings_by_severity = {}
        
        for asset in assets:
            matches = self.match_asset(asset)
            all_matches.extend(matches)
            
            for match in matches:
                # Track by criticality
                crit = match.criticality.lower()
                if crit not in findings_by_criticality:
                    findings_by_criticality[crit] = 0
                findings_by_criticality[crit] += 1
                
                # Track by severity
                sev = (match.severity or "Unknown").lower()
                if sev not in findings_by_severity:
                    findings_by_severity[sev] = 0
                findings_by_severity[sev] += 1
        
        # Save findings if requested
        if save_findings:
            self._save_findings(all_matches)
        
        return {
            "total_matches": len(all_matches),
            "total_assets_checked": len(assets),
            "assets_with_findings": len(set(m.asset_id for m in all_matches)),
            "findings_by_criticality": findings_by_criticality,
            "findings_by_severity": findings_by_severity,
            "matches": all_matches,
        }
    
    def _save_findings(self, matches: list[Match]) -> None:
        """Save matches as Finding records in database, preserving remediation data."""
        
        # Save existing remediation data before clearing
        old_findings = self.session.query(Finding).all()
        remediation_map = {}
        for old_finding in old_findings:
            key = (old_finding.cve_id, old_finding.matched_asset)
            remediation_map[key] = {
                'remediation_status': old_finding.remediation_status,
                'patched_version': old_finding.patched_version,
                'patched_at': old_finding.patched_at,
                'remediation_notes': old_finding.remediation_notes,
            }
        
        # Clear existing findings to avoid duplicates
        self.session.query(Finding).delete()
        
        for match in matches:
            match_details = {
                "asset_type": match.asset_type,
                "site": match.site,
                "role": match.role,
                "infra_cpe": match.infra_cpe,
                "cve_cpe": match.cve_cpe,
                "match_confidence": match.match_confidence,
                "match_reason": match.match_reason,
                "version_vulnerable": match.version_vulnerable,
                "internet_exposed": match.internet_exposed,
                "criticality": match.criticality,
                "cvss_v3_score": match.cvss_v3_score,
            }
            
            # Get remediation data if it existed before
            cve_id = match.cve_obj.id if match.cve_obj else None
            remediation_key = (cve_id, match.asset_id)
            remediation = remediation_map.get(remediation_key, {})
            
            finding = Finding(
                cve_id=cve_id,
                cpe_uri=match.cve_cpe,
                matched_asset=match.asset_id,
                match_details=json.dumps(match_details),
                created_at=datetime.datetime.utcnow(),
                remediation_status=remediation.get('remediation_status'),
                patched_version=remediation.get('patched_version'),
                patched_at=remediation.get('patched_at'),
                remediation_notes=remediation.get('remediation_notes'),
            )
            self.session.add(finding)
        
        self.session.commit()
        print(f"Saved {len(matches)} findings to database (preserved {len(remediation_map)} remediation records)")
