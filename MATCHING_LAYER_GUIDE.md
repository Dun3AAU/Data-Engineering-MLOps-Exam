# CVE-to-Infrastructure Matching Layer - Implementation Guide

## Overview

A complete matching layer has been implemented in `backend/API/` that:
1. **Extracts** CPEs from infrastructure inventory (servers, workstations, network devices)
2. **Matches** infrastructure CPEs to CVE vulnerabilities in the NVD database
3. **Stores** findings with confidence scores and metadata
4. **Provides** data structures ready for LLM-based reasoning

## Architecture

```
Infrastructure Inventory     CVE Database
(JSON files)                 (SQLite)
     │                            │
     ├─ servers.json              │
     ├─ workstations.json         │
     └─ network.json       CVE Records (302K+)
                           CPE Matches (2.5M+)
                                  │
                    ┌─────────────┴──────────────┐
                    ▼                            ▼
            infrastructure_extractor.py    cpe_utils.py
                    │                            │
                    └────────────┬───────────────┘
                                 ▼
                         matcher.py
                                 │
                    ┌────────────┴──────────────┐
                    ▼                          ▼
             Finding Records                LLM Layer
             (845 matches)            (Next: reasoning)
```

## Implementation Details

### 1. CPE Utilities (`cpe_utils.py`)

**Purpose**: Handle CPE parsing, normalization, and matching

**Key Classes/Functions**:
- `CPEParts` - Dataclass for parsed CPE components
- `parse_cpe_uri()` - Parse CPE 2.3 URI
- `normalize_cpe_component()` - Handle case, spaces, special chars
- `version_matches_range()` - Check if version in vulnerable range
- `generate_cpes_for_asset()` - Create multiple CPE variants

**Example**:
```python
# Parse Windows Server 2019 CPE
cpe = parse_cpe_uri("cpe:2.3:o:microsoft:windows_server:2019:*:*:*:*:*:*:*:*")

# Check if version 2019 is vulnerable (ranges: 2019-2021)
if version_matches_range("2019", "2019", "2021"):
    print("VULNERABLE!")

# Generate search variants
cpes = generate_cpes_for_asset(
    "Microsoft", 
    "Windows Server", 
    "2019",
    asset_type="o"
)
```

### 2. Infrastructure Extractor (`infrastructure_extractor.py`)

**Purpose**: Load infrastructure JSON and extract CPEs

**Key Class**: `InfrastructureExtractor`

**Handles**:
- Servers: OS + installed software
- Workstations: OS + installed software  
- Network devices: Vendor/product + firmware

**Output**: `InfrastructureAsset` objects with:
- `asset_id` - Hostname
- `asset_type` - "server"/"workstation"/"network_device"
- `cpes` - List of generated CPE URIs
- `criticality` - Asset importance
- `internet_exposed` - Network boundary status

**Example**:
```python
extractor = InfrastructureExtractor("backend/infrastructure")
assets = extractor.extract_all()

# 25 total assets extracted with 69 CPEs
print(f"Extracted {len(assets)} assets")
for asset in assets:
    print(f"{asset.asset_id}: {len(asset.cpes)} CPEs")
```

### 3. Matching Engine (`matcher.py`)

**Purpose**: Match infrastructure CPEs to CVE vulnerabilities

**Key Class**: `CVEInfrastructureMatcher`

**Matching Logic**:
1. For each infrastructure asset's CPEs
2. Query database for CPE matches (optimized with ILIKE on vendor:product)
3. Validate version ranges
4. Calculate confidence score (0-1.0)
5. Store as Finding

**Confidence Calculation**:
- Part match (OS vs App): +0.3
- Vendor match: +0.2
- Product match: +0.2
- Version vulnerable: +0.3

**Example**:
```python
matcher = CVEInfrastructureMatcher(session)

# Match single asset
matches = matcher.match_asset(asset)

# Match all assets
results = matcher.match_all_assets(assets, save_findings=True)
print(f"Found {results['total_matches']} vulnerabilities")
```

## Running the System

### Main Workflow

```bash
# 1. Extract infrastructure
cd backend/infrastructure
# (JSON files already present)

# 2. Populate CVE database (one-time)
python backend/API/scripts/populate_db.py

# 3. Run matching
python backend/API/scripts/match_infrastructure.py

# 4. Query results
python backend/API/scripts/query_findings.py
```

### Command Reference

```bash
# Activate environment
source .venv/bin/activate

# Run full matching pipeline
python backend/API/scripts/match_infrastructure.py

# Update CVE database (incremental)
python backend/API/scripts/update_db.py

# Explore database statistics
python backend/API/scripts/explore_db.py

# Query findings for LLM
python backend/API/scripts/query_findings.py
```

## Sample Results

From test run with 25 infrastructure assets:

```
Total matches found: 845
Assets checked: 25
Assets with findings: 13

Findings by severity:
  - High: 35
  - Medium: 216
  - Low: 1
  - Unknown: 593

Most affected assets:
  - ERP01 (CRITICAL): 192 vulnerabilities
  - RDS01 (HIGH): 172 vulnerabilities
  - BAK01 (HIGH): 172 vulnerabilities
  - ACC01 (MEDIUM): 49 vulnerabilities

Internet-exposed: 11 vulnerabilities in MAIL01
```

## Database Schema

### CVE Table
```sql
CREATE TABLE cves (
    id INTEGER PRIMARY KEY,
    cve_id VARCHAR UNIQUE,
    published_date DATETIME,
    severity VARCHAR,
    cvss_v3_score FLOAT,
    ...
);
```

### CPEMatch Table
```sql
CREATE TABLE cpe_matches (
    id INTEGER PRIMARY KEY,
    cve_id INTEGER FOREIGN KEY,
    cpe23Uri TEXT,
    versionStartIncluding VARCHAR,
    versionEndIncluding VARCHAR,
    ...
);
```

### Finding Table
```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    cve_id INTEGER,
    matched_asset VARCHAR,
    match_details JSON,
    created_at DATETIME,
    ...
);
```

## Integration with LLM Layer

The findings provide structured input for LLM reasoning:

```python
from backend.API.db import get_session
from backend.API.models import Finding
import json

session = get_session()
findings = session.query(Finding).all()

for finding in findings:
    details = json.loads(finding.match_details)
    
    # Pass to LLM for reasoning
    context = {
        'cve': finding.cve_id,
        'asset': finding.matched_asset,
        'severity': details['severity'],
        'cvss': details['cvss_v3_score'],
        'asset_criticality': details['criticality'],
        'internet_exposed': details['internet_exposed'],
        'confidence': details['match_confidence'],
    }
    
    # LLM can then assess:
    # - Business impact
    # - Remediation options
    # - Risk prioritization
    # - SLA compliance
```

## Performance Characteristics

| Metric | Value |
|--------|-------|
| CVEs in database | 302,111 |
| CPE matches in database | 2,518,017 |
| Infrastructure assets | 25 |
| Extracted CPEs | 69 |
| Matching time | ~10 seconds |
| Total findings | 845 |
| Query efficiency | ILIKE index on cpe23Uri |

## Normalization Approach

The system handles common CPE variations:

| Original | Normalized |
|----------|------------|
| "Microsoft" | "microsoft" |
| "Windows Server" | "windows_server" |
| "Office 2019" | "office_2019" |
| "23H2" (Win11) | (23, 2) for comparison |
| "10.0.17763" | (10, 0, 17763) |

## Known Limitations & Future Work

### Current State
- Mock infrastructure data only
- No baseline/remediation tracking
- All findings regenerated on each run

### Improvements Needed
1. **Incremental updates**: Only process new CVEs
2. **Caching**: Cache infrastructure->CPE mappings
3. **Dynamic criticality**: Update from real CMDB
4. **Remediation tracking**: Store patch status
5. **Risk scoring**: Multi-factor risk assessment
6. **Alerting**: Real-time HIGH/CRITICAL findings

## Code Structure

```
backend/API/
├── models.py              # SQLAlchemy models
├── db.py                  # Database config
├── ingest.py              # NVD API ingestion
│
├── cpe_utils.py          # CPE parsing/matching (NEW)
├── infrastructure_extractor.py  # Asset extraction (NEW)
├── matcher.py            # Matching engine (NEW)
│
├── scripts/
│   ├── populate_db.py
│   ├── update_db.py
│   ├── explore_db.py
│   ├── match_infrastructure.py   # Main runner (NEW)
│   └── query_findings.py         # LLM preparation (NEW)
│
└── README.md             # Updated with matching layer
```

## Next Steps

1. **Validate Results**: Test matching against known vulnerabilities
2. **Fine-tune Thresholds**: Adjust confidence/severity filters
3. **Performance**: Profile and optimize for larger databases
4. **Integrate LLM**: Connect to reasoning layer
5. **Automate**: Setup scheduled matching jobs
6. **Dashboard**: Create visualization of findings

## Questions?

Refer to:
- `backend/API/README.md` - Complete API documentation
- `backend/API/cpe_utils.py` - Detailed docstrings
- `backend/API/matcher.py` - Matching logic explanation
- `/memories/repo/matching_layer.md` - Technical summary
