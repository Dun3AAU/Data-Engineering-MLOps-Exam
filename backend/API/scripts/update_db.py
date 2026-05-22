"""Incremental updater for the NVD CVE dataset with logging and artifact capture.

This script writes a rotating log to `data/log/update.log`, creates a DB
snapshot in `data/db`, and writes a run summary JSON to
`data/log/update_summary.json`.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API import ingest
from backend.API.db import get_session
from backend.API.models import CVE


DATA_DIR = ROOT / "data"
DB_DIR = DATA_DIR / "db"
LOG_DIR = DATA_DIR / "log"
LOG_PATH = LOG_DIR / "update.log"
SUMMARY_PATH = LOG_DIR / "update_summary.json"
SOURCE_DB_PATH = DB_DIR / "cve.db"

def setup_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("update_db")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # also log to stdout
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_latest_modified(session) -> datetime | None:
    row = session.query(CVE).order_by(CVE.last_modified_date.desc()).first()
    if not row or not row.last_modified_date:
        return None
    if row.last_modified_date.tzinfo is None:
        return row.last_modified_date.replace(tzinfo=timezone.utc)
    return row.last_modified_date


def main(sleep_seconds: float = 6.0, bootstrap_if_empty: bool = True, logger: logging.Logger | None = None) -> None:
    if logger is None:
        logger = setup_logger()

    ingest.init_db()
    session = get_session()
    start_time = datetime.now(timezone.utc)
    summary = {
        "start_time": start_time.isoformat(),
        "new": 0,
        "updated": 0,
        "processed": 0,
        "start_index": None,
        "end_index": None,
    }

    try:
        latest = get_latest_modified(session)
        if latest is None:
            if not bootstrap_if_empty:
                logger.error("Database is empty; run the historical populate script first.")
                raise RuntimeError("Database is empty; run the historical populate script first.")
            logger.info("Database is empty; running a full bootstrap instead of an incremental update.")
            for batch in ingest.iter_cves(sleep_seconds=sleep_seconds):
                vulnerabilities = batch["vulnerabilities"]
                logger.info(
                    "Bootstrap fetch: startIndex=%d totalResults=%d count=%d",
                    batch["start_index"],
                    batch["total_results"],
                    len(vulnerabilities),
                )
                if summary["start_index"] is None:
                    summary["start_index"] = batch["start_index"]
                summary["end_index"] = batch["start_index"]
                for vulnerability in vulnerabilities:
                    created = ingest.upsert_cve(session, vulnerability)
                    if created:
                        summary["new"] += 1
                    else:
                        summary["updated"] += 1
                    summary["processed"] += 1
                session.commit()
            return

        last_mod_end = datetime.now(timezone.utc)
        logger.info("Fetching CVEs modified between %s and %s", latest.isoformat(), last_mod_end.isoformat())
        for batch in ingest.iter_cves(
            last_mod_start=latest,
            last_mod_end=last_mod_end,
            sleep_seconds=sleep_seconds,
        ):
            vulnerabilities = batch["vulnerabilities"]
            logger.info(
                "Incremental fetch: startIndex=%d totalResults=%d count=%d",
                batch["start_index"],
                batch["total_results"],
                len(vulnerabilities),
            )
            if summary["start_index"] is None:
                summary["start_index"] = batch["start_index"]
            summary["end_index"] = batch["start_index"]
            for vulnerability in vulnerabilities:
                created = ingest.upsert_cve(session, vulnerability)
                if created:
                    summary["new"] += 1
                else:
                    summary["updated"] += 1
                summary["processed"] += 1
            session.commit()
    except Exception:
        logger.exception("Unhandled error during update run")
        raise
    finally:
        session.close()

    end_time = datetime.now(timezone.utc)
    summary.update({"end_time": end_time.isoformat()})

    # snapshot DB
    try:
        snapshot_name = f"cve-{end_time.strftime('%Y%m%d-%H%M%S')}.db"
        DB_DIR.mkdir(parents=True, exist_ok=True)
        snapshot_path = DB_DIR / snapshot_name
        shutil.copy2(SOURCE_DB_PATH, snapshot_path)
        logger.info("DB snapshot written to %s", snapshot_path)
        summary["snapshot"] = str(snapshot_path)
    except Exception:
        logger.exception("Failed to write DB snapshot")

    # write summary JSON
    try:
        with open(SUMMARY_PATH, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        logger.info("Run summary written to %s", SUMMARY_PATH)
    except Exception:
        logger.exception("Failed to write update summary")

    logger.info("Update complete. Processed=%d new=%d updated=%d", summary["processed"], summary["new"], summary["updated"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sleep-seconds", type=float, default=ingest.DEFAULT_SLEEP_SECONDS)
    parser.add_argument("--no-bootstrap", action="store_true")
    arguments = parser.parse_args()
    main(arguments.sleep_seconds, bootstrap_if_empty=not arguments.no_bootstrap)
