This folder contains utilities to ingest CVE data from the NVD API into a local SQLite database.

Generated data lives under `data/db` and `data/log` at the repository root.

Quick start

- Install runtime dependencies (recommended into a virtualenv):

```bash
python -m pip install -r requirements.txt
```

- Populate historical CVEs (example):

```bash
python backend/API/scripts/populate_db.py
```

- Run daily updates (example):

```bash
python backend/API/scripts/update_db.py
```

The scripts use the NVD CVE API at `https://services.nvd.nist.gov/rest/json/cves/2.0`, do not require an API key, and sleep 6 seconds between requests to stay within the published rate limits.

If you run the updater on a fresh database, it will bootstrap the full dataset once and then continue incrementally on later runs.

---

## CVE Infrastructure Matching Layer

The API module now includes a complete matching system that connects infrastructure inventory to CVE vulnerabilities via CPE (Common Platform Enumeration).

### Components

- **`cpe_utils.py`** - CPE parsing, normalization, and version matching
- **`infrastructure_extractor.py`** - Extract CPEs from JSON inventory files
- **`matcher.py`** - Match infrastructure assets to CVEs
- **`scripts/match_infrastructure.py`** - Runner script for the full matching pipeline

### Quick Start - Run Matching

```bash
# Run the complete matching pipeline
python backend/API/scripts/match_infrastructure.py
```

This will:
1. Load infrastructure from `backend/infrastructure/`
2. Extract CPEs from servers, workstations, and network devices
3. Match against the CVE database
4. Save findings to the database
5. Report vulnerabilities by severity and asset criticality

### Example Output

```
Total matches found: 845
Assets checked: 25
Assets with findings: 13

Findings by severity:
  - High: 35
  - Medium: 216
  - Low: 1
  - Unknown: 593
```

### Database Models

**Finding** table stores matching results:
- `cve_id` - Reference to CVE
- `matched_asset` - Infrastructure asset ID
- `match_details` - JSON with match metadata (confidence, reasons, etc.)
- `created_at` - When the finding was created

### Usage in Code

```python
from backend.API.matcher import CVEInfrastructureMatcher
from backend.API.infrastructure_extractor import InfrastructureExtractor
from backend.API.db import get_session

# Extract infrastructure
extractor = InfrastructureExtractor("backend/infrastructure")
assets = extractor.extract_all()

# Match to CVEs
session = get_session()
matcher = CVEInfrastructureMatcher(session)
results = matcher.match_all_assets(assets, save_findings=True)

print(f"Found {results['total_matches']} vulnerabilities")
```

### Query Results

```python
from backend.API.db import get_session
from backend.API.models import Finding
import json

session = get_session()

# Find critical + high severity findings
findings = session.query(Finding).all()
critical_high = [
    f for f in findings
    if json.loads(f.match_details)['severity'] in ['CRITICAL', 'HIGH']
]

print(f"Critical/High vulnerabilities: {len(critical_high)}")
```

### Integration with LLM Layer

The Finding table provides structured input for LLM reasoning:
- CVE details (severity, CVSS score)
- Asset info (criticality, internet exposure)
- Match confidence and reasoning
- Ready for risk assessment and remediation recommendations
