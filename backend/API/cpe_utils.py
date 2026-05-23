"""CPE (Common Platform Enumeration) utilities for parsing, normalizing, and matching."""

from dataclasses import dataclass
from typing import Optional, Tuple
import re


@dataclass
class CPEParts:
    """Parsed CPE 2.3 URI components."""
    part: str  # a (application), o (os), h (hardware)
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_uri(self) -> str:
        """Convert back to CPE 2.3 URI format."""
        return (
            f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:"
            f"{self.update}:{self.edition}:{self.language}:{self.sw_edition}:"
            f"{self.target_sw}:{self.target_hw}:{self.other}"
        )


def normalize_cpe_component(value: str) -> str:
    """
    Normalize a CPE component by:
    - Converting to lowercase
    - Replacing spaces/underscores with single character
    - Removing special characters except hyphen and underscore
    - Handling common variations
    """
    if not value or value == "*":
        return "*"
    
    # Replace common variant spellings
    value = value.lower().strip()
    value = re.sub(r'\s+', '_', value)  # spaces to underscores
    value = re.sub(r'[^a-z0-9._\-]', '', value)  # remove special chars
    value = re.sub(r'_+', '_', value)  # collapse multiple underscores
    
    return value


def parse_cpe_uri(uri: str) -> Optional[CPEParts]:
    """
    Parse a CPE 2.3 URI into components.
    
    Example: cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*:*
    """
    if not uri.startswith("cpe:2.3:"):
        return None
    
    parts = uri[8:].split(":")
    if len(parts) < 5:
        return None
    
    # Pad with wildcards if needed
    while len(parts) < 11:
        parts.append("*")
    
    return CPEParts(
        part=parts[0],
        vendor=parts[1],
        product=parts[2],
        version=parts[3],
        update=parts[4] if len(parts) > 4 else "*",
        edition=parts[5] if len(parts) > 5 else "*",
        language=parts[6] if len(parts) > 6 else "*",
        sw_edition=parts[7] if len(parts) > 7 else "*",
        target_sw=parts[8] if len(parts) > 8 else "*",
        target_hw=parts[9] if len(parts) > 9 else "*",
        other=parts[10] if len(parts) > 10 else "*",
    )


def normalize_cpe_uri(uri: str) -> Optional[str]:
    """Normalize a CPE URI for comparison."""
    parsed = parse_cpe_uri(uri)
    if not parsed:
        return None
    
    # Normalize components
    parsed.vendor = normalize_cpe_component(parsed.vendor)
    parsed.product = normalize_cpe_component(parsed.product)
    parsed.version = normalize_cpe_component(parsed.version)
    
    return parsed.to_uri()


def parse_version(version: str) -> Tuple[int, ...]:
    """
    Parse version string into tuple of integers for comparison.
    
    Examples:
    - "2019" -> (2019,)
    - "10.0.17763" -> (10, 0, 17763)
    - "1.2.3.4.5" -> (1, 2, 3, 4, 5)
    - "23H2" -> (23, 2)  # H2 = semester 2, treated as 2
    """
    # Handle Windows 11 style versions (e.g., "23H2")
    version = version.strip().upper()
    version = re.sub(r'H(\d)', r'.\1', version)  # "23H2" -> "23.2"
    
    # Extract all numeric components
    parts = []
    for part in version.split("."):
        # Try to extract leading digits
        match = re.match(r'(\d+)', part)
        if match:
            parts.append(int(match.group(1)))
        elif part == "SP1":
            parts.append(1)
        elif part == "SP2":
            parts.append(2)
        else:
            parts.append(0)  # Default for non-numeric parts
    
    return tuple(parts) if parts else (0,)


def version_matches_range(
    version: str,
    version_start_including: Optional[str] = None,
    version_end_including: Optional[str] = None,
) -> bool:
    """
    Check if a version falls within a range specified by >= and <=.
    
    Args:
        version: The version to check (e.g., "10.0.17763")
        version_start_including: Minimum version (inclusive), None means no lower bound
        version_end_including: Maximum version (inclusive), None means no upper bound
    
    Returns:
        True if version is within range, False otherwise
    """
    parsed_version = parse_version(version)
    
    if version_start_including:
        parsed_start = parse_version(version_start_including)
        if parsed_version < parsed_start:
            return False
    
    if version_end_including:
        parsed_end = parse_version(version_end_including)
        if parsed_version > parsed_end:
            return False
    
    return True


def cpe_components_match(
    infra_cpe: str,
    cve_cpe: str,
    strict: bool = False
) -> bool:
    """
    Check if infrastructure CPE matches CVE CPE.
    
    Args:
        infra_cpe: CPE from infrastructure inventory
        cve_cpe: CPE from CVE match
        strict: If True, require exact match of all components; if False, allow wildcards
    
    Returns:
        True if CPEs match (accounting for wildcards and normalization)
    """
    infra_parsed = parse_cpe_uri(infra_cpe)
    cve_parsed = parse_cpe_uri(cve_cpe)
    
    if not infra_parsed or not cve_parsed:
        return False
    
    # Normalize components for comparison
    def compare_component(infra_val: str, cve_val: str) -> bool:
        # If CVE component is wildcard, it matches anything
        if cve_val == "*":
            return True
        # If infrastructure component is wildcard, must match CVE exactly (or CVE is also wildcard)
        if infra_val == "*":
            return False
        
        # Normalize and compare
        infra_norm = normalize_cpe_component(infra_val)
        cve_norm = normalize_cpe_component(cve_val)
        return infra_norm == cve_norm
    
    # Must match: part, vendor, product
    if not compare_component(infra_parsed.part, cve_parsed.part):
        return False
    if not compare_component(infra_parsed.vendor, cve_parsed.vendor):
        return False
    if not compare_component(infra_parsed.product, cve_parsed.product):
        return False
    
    # Version is optional - if CVE specifies version, must match
    if cve_parsed.version != "*" and infra_parsed.version != "*":
        if not compare_component(infra_parsed.version, cve_parsed.version):
            return False
    
    return True


def generate_cpes_for_asset(
    vendor: str,
    product: str,
    version: str,
    asset_type: str = "a"
) -> list[str]:
    """
    Generate possible CPE URIs for an asset.
    
    This creates multiple variations to handle common normalization issues:
    - Original values
    - Lowercase versions
    - With/without spaces
    
    Args:
        vendor: Vendor name
        product: Product name
        version: Version string
        asset_type: 'a' for application, 'o' for OS, 'h' for hardware
    
    Returns:
        List of CPE URIs to search for
    """
    cpes = set()
    
    # Create variations of vendor/product
    variants = []
    for v in [vendor, vendor.replace(" ", "_"), vendor.lower()]:
        for p in [product, product.replace(" ", "_"), product.lower()]:
            for ve in [version, version.replace(" ", "_"), version.lower()]:
                variants.append((v, p, ve))
    
    # Normalize and create CPEs
    for v, p, ve in variants:
        normalized_cpe = (
            f"cpe:2.3:{asset_type}:"
            f"{normalize_cpe_component(v)}:"
            f"{normalize_cpe_component(p)}:"
            f"{normalize_cpe_component(ve)}:*:*:*:*:*:*:*"
        )
        cpes.add(normalized_cpe)
    
    return list(cpes)
