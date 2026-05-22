"""One-shot script to populate the SQLite DB with the historical NVD CVE dataset."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API import ingest
from backend.API.db import get_session


def main(sleep_seconds: float = 6.0, start_index: int = 0) -> None:
    ingest.init_db()
    session = get_session()

    try:
        if start_index > 0:
            print(f"Starting from index {start_index:,}")

        pending = 0
        for batch in ingest.iter_cves(start_index=start_index, sleep_seconds=sleep_seconds):
            vulnerabilities = batch["vulnerabilities"]
            print(
                f"Fetching historical CVEs: startIndex={batch['start_index']:,} totalResults={batch['total_results']:,} count={len(vulnerabilities)}"
            )
            for vulnerability in vulnerabilities:
                ingest.upsert_cve(session, vulnerability)
                pending += 1
                if pending >= 100:
                    session.commit()
                    pending = 0

            if pending:
                session.commit()
                pending = 0
    finally:
        session.close()

    print("Historical population complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Populate CVE database from NVD API")
    parser.add_argument("--sleep-seconds", type=float, default=ingest.DEFAULT_SLEEP_SECONDS)
    parser.add_argument("--start-index", type=int, default=0, help="Start pagination from this index (default: 0)")
    arguments = parser.parse_args()

    main(arguments.sleep_seconds, arguments.start_index)
