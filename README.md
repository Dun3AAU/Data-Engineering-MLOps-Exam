## Repo Plan

This repository is organized around a small Python ingestion pipeline plus room for a future frontend.

### Source Layout

- `backend/API/` contains the CVE ingestion logic, database setup, and command-line scripts.
- `backend/infrastructure/` contains the mock company and asset JSON inputs.
- `frontend/` is reserved for a UI if you add one later.
- `.github/workflows/` contains the scheduled CVE update job.

### Data Layout

- `data/db/` stores the live SQLite database and timestamped snapshots.
- `data/log/` stores the updater log and run summary JSON.
- Both `data/db/` and `data/log/` are generated at runtime and should stay out of git.

### Working Commands

```bash
python backend/API/scripts/populate_db.py
python backend/API/scripts/update_db.py
```

The updater bootstraps the database if it is empty, then switches to incremental updates on later runs.
