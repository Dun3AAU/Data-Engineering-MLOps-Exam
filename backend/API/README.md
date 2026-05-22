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
