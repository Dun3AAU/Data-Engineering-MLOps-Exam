"""Extract CPE information from infrastructure JSON files."""

from pathlib import Path
import json
from dataclasses import dataclass

from .cpe_utils import generate_cpes_for_asset


@dataclass
class InfrastructureAsset:
    """Represents an asset in the infrastructure inventory."""
    asset_id: str  # Unique identifier (hostname, etc.)
    asset_type: str  # "server", "workstation", "network_device"
    site: str
    role: str
    criticality: str
    internet_exposed: bool
    cpes: list[str]  # Generated CPE URIs
    raw_data: dict  # Original data for reference


class InfrastructureExtractor:
    """Extract CPEs and assets from infrastructure JSON files."""
    
    def __init__(self, infrastructure_dir: Path):
        """Initialize with path to infrastructure directory."""
        self.infra_dir = Path(infrastructure_dir)
        self.assets: list[InfrastructureAsset] = []
    
    def extract_all(self) -> list[InfrastructureAsset]:
        """Extract all assets from infrastructure files."""
        self.assets = []
        
        # Load servers
        servers_file = self.infra_dir / "assets" / "servers.json"
        if servers_file.exists():
            self._extract_servers(servers_file)
        
        # Load workstations
        workstations_file = self.infra_dir / "assets" / "workstations.json"
        if workstations_file.exists():
            self._extract_workstations(workstations_file)
        
        # Load network devices
        network_file = self.infra_dir / "assets" / "network.json"
        if network_file.exists():
            self._extract_network_devices(network_file)
        
        return self.assets
    
    def _extract_servers(self, filepath: Path) -> None:
        """Extract CPEs from servers.json."""
        with open(filepath) as f:
            data = json.load(f)
        
        for server in data.get("servers", []):
            cpes = []
            
            # OS CPE
            if "os" in server:
                os_info = server["os"]
                os_name = os_info.get("name", "")
                os_version = os_info.get("version", "")
                
                if os_name and os_version:
                    cpes.extend(generate_cpes_for_asset(
                        vendor=self._vendor_from_os(os_name),
                        product=os_name,
                        version=os_version,
                        asset_type="o"
                    ))
            
            # Installed software CPEs
            for software in server.get("installed_software", []):
                vendor = software.get("vendor", "")
                product = software.get("product", "")
                version = software.get("version", "")
                
                if vendor and product and version:
                    cpes.extend(generate_cpes_for_asset(
                        vendor=vendor,
                        product=product,
                        version=version,
                        asset_type="a"
                    ))
            
            if cpes:
                asset = InfrastructureAsset(
                    asset_id=server.get("hostname", "unknown"),
                    asset_type="server",
                    site=server.get("site", "unknown"),
                    role=server.get("role", ""),
                    criticality=server.get("criticality", "unknown"),
                    internet_exposed=server.get("internet_exposed", False),
                    cpes=cpes,
                    raw_data=server
                )
                self.assets.append(asset)
    
    def _extract_workstations(self, filepath: Path) -> None:
        """Extract CPEs from workstations.json."""
        with open(filepath) as f:
            data = json.load(f)
        
        for ws in data.get("workstations", []):
            cpes = []
            
            # OS CPE
            if "os" in ws:
                os_info = ws["os"]
                os_name = os_info.get("name", "")
                os_version = os_info.get("version", "")
                
                if os_name and os_version:
                    cpes.extend(generate_cpes_for_asset(
                        vendor=self._vendor_from_os(os_name),
                        product=os_name,
                        version=os_version,
                        asset_type="o"
                    ))
            
            # Installed software CPEs
            for software in ws.get("installed_software", []):
                vendor = software.get("vendor", "")
                product = software.get("product", "")
                version = software.get("version", "")
                
                if vendor and product and version:
                    cpes.extend(generate_cpes_for_asset(
                        vendor=vendor,
                        product=product,
                        version=version,
                        asset_type="a"
                    ))
            
            if cpes:
                asset = InfrastructureAsset(
                    asset_id=ws.get("hostname", "unknown"),
                    asset_type="workstation",
                    site=ws.get("site", "unknown"),
                    role=ws.get("type", ""),
                    criticality=ws.get("criticality", "unknown"),
                    internet_exposed=ws.get("internet_exposed", False),
                    cpes=cpes,
                    raw_data=ws
                )
                self.assets.append(asset)
    
    def _extract_network_devices(self, filepath: Path) -> None:
        """Extract CPEs from network.json."""
        with open(filepath) as f:
            data = json.load(f)
        
        for device in data.get("network_devices", []):
            cpes = []
            
            vendor = device.get("vendor", "")
            product = device.get("product", "")
            firmware_version = device.get("firmware_version", "")
            
            if vendor and product and firmware_version:
                cpes.extend(generate_cpes_for_asset(
                    vendor=vendor,
                    product=product,
                    version=firmware_version,
                    asset_type="h"  # hardware
                ))
            
            if cpes:
                asset = InfrastructureAsset(
                    asset_id=device.get("hostname", "unknown"),
                    asset_type="network_device",
                    site=device.get("site", "unknown"),
                    role=device.get("role", ""),
                    criticality=device.get("criticality", "unknown"),
                    internet_exposed=device.get("internet_exposed", False),
                    cpes=cpes,
                    raw_data=device
                )
                self.assets.append(asset)
    
    @staticmethod
    def _vendor_from_os(os_name: str) -> str:
        """Infer vendor from OS name."""
        os_lower = os_name.lower()
        if "windows" in os_lower:
            return "Microsoft"
        elif "ubuntu" in os_lower or "debian" in os_lower:
            return "Debian"
        elif "rhel" in os_lower or "centos" in os_lower or "fedora" in os_lower:
            return "RedHat"
        elif "macos" in os_lower or "osx" in os_lower:
            return "Apple"
        else:
            return os_name.split()[0]  # First word as vendor
