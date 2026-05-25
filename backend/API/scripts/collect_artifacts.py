#!/usr/bin/env python3
"""Refresh NVD data, rematch infrastructure, run reasoning, and collect artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.models import CVE, Finding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the NVD -> match -> reasoning pipeline and collect artifacts")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "artifacts", help="Directory that will receive the collected bundle")
    parser.add_argument("--nvd-sleep-seconds", type=float, default=0.0, help="Sleep between NVD requests")
    parser.add_argument("--nvd-start-index", type=int, default=None, help="Start index for NVD bootstrap when DB is empty")
    parser.add_argument("--skip-update", action="store_true", help="Skip NVD update_db.py")
    parser.add_argument("--skip-match", action="store_true", help="Skip infrastructure matching")
    parser.add_argument("--skip-reasoning", action="store_true", help="Skip LLM reasoning")
    parser.add_argument("--reasoning-limit", type=int, default=50, help="Maximum findings to send to the reasoning layer")
    parser.add_argument("--reasoning-all", action="store_true", help="Send all open findings to the reasoning layer")
    parser.add_argument("--reasoning-dry-run", action="store_true", help="Use heuristic reasoning instead of Groq")
    parser.add_argument("--reasoning-model", type=str, default=None, help="Override the reasoning model")
    return parser.parse_args()


def run_step(label: str, command: list[str]) -> None:
    print(f"\n==> {label}")
    print(" ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def copy_tree(source: Path, destination: Path) -> bool:
    if not source.exists():
        return False
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    return True


def latest_snapshot() -> Path | None:
    db_dir = ROOT / "data" / "db"
    snapshots = sorted(db_dir.glob("cve-*.db"))
    return snapshots[-1] if snapshots else None


def parse_match_details(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def build_matching_summary() -> dict:
    session = get_session()
    try:
        rows = session.query(Finding, CVE).join(CVE, Finding.cve_id == CVE.id).all()
        by_severity: dict[str, int] = defaultdict(int)
        by_criticality: dict[str, int] = defaultdict(int)
        by_asset_type: dict[str, int] = defaultdict(int)
        internet_exposed_count = 0
        asset_rollup: dict[str, dict[str, object]] = defaultdict(lambda: {
            "finding_count": 0,
            "criticality": "low",
            "internet_exposed": False,
        })
        cve_rollup: dict[str, dict[str, object]] = defaultdict(lambda: {
            "finding_count": 0,
            "max_cvss": 0.0,
        })

        def max_criticality(current: str, incoming: str) -> str:
            weights = {"critical": 40, "high": 25, "medium": 10, "low": 0}
            return incoming if weights.get(incoming, 0) > weights.get(current, 0) else current

        for finding, cve in rows:
            details = parse_match_details(finding.match_details)
            criticality = str(details.get("criticality") or "low").lower()
            asset_type = str(details.get("asset_type") or "unknown")
            severity = str(cve.severity or "unknown").lower()

            if details.get("internet_exposed"):
                internet_exposed_count += 1

            by_severity[severity] += 1
            by_criticality[criticality] += 1
            by_asset_type[asset_type] += 1

            asset_id = finding.matched_asset or "unknown"
            asset_entry = asset_rollup[asset_id]
            asset_entry["finding_count"] = int(asset_entry["finding_count"]) + 1
            asset_entry["internet_exposed"] = bool(asset_entry["internet_exposed"]) or bool(details.get("internet_exposed"))
            asset_entry["criticality"] = max_criticality(str(asset_entry["criticality"]), criticality)

            cve_entry = cve_rollup[cve.cve_id]
            cve_entry["finding_count"] = int(cve_entry["finding_count"]) + 1
            cve_entry["max_cvss"] = max(float(cve_entry["max_cvss"]), float(cve.cvss_v3_score or 0.0))

        top_assets = sorted(
            ({"asset_id": asset_id, **entry} for asset_id, entry in asset_rollup.items()),
            key=lambda item: (-int(item["finding_count"]), item["asset_id"]),
        )[:10]
        top_cves = sorted(
            ({"cve_id": cve_id, **entry} for cve_id, entry in cve_rollup.items()),
            key=lambda item: (-int(item["finding_count"]), -float(item["max_cvss"])),
        )[:10]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(rows),
            "by_severity": dict(sorted(by_severity.items(), key=lambda item: item[0])),
            "by_criticality": dict(sorted(by_criticality.items(), key=lambda item: item[0])),
            "by_asset_type": dict(sorted(by_asset_type.items(), key=lambda item: item[0])),
            "internet_exposed_count": internet_exposed_count,
            "top_assets": top_assets,
            "top_cves": top_cves,
        }
    finally:
        session.close()


def collect_artifacts(artifact_dir: Path) -> dict:
    artifact_dir.mkdir(parents=True, exist_ok=True)

    copied: list[dict[str, str]] = []
    tree_pairs = [
        (ROOT / "data" / "db", artifact_dir / "data" / "db"),
        (ROOT / "data" / "log", artifact_dir / "data" / "log"),
        (ROOT / "backend" / "API" / "reasoning" / "output", artifact_dir / "backend" / "API" / "reasoning" / "output"),
        (ROOT / "backend" / "infrastructure", artifact_dir / "backend" / "infrastructure"),
        (ROOT / "frontend", artifact_dir / "frontend"),
    ]

    for source, destination in tree_pairs:
        if copy_tree(source, destination):
            copied.append({"source": str(source), "destination": str(destination)})

    snapshot = latest_snapshot()
    if snapshot is not None:
        target_snapshot = artifact_dir / "data" / "db" / snapshot.name
        target_snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snapshot, target_snapshot)
        copied.append({"source": str(snapshot), "destination": str(target_snapshot)})

    matching_summary = build_matching_summary()
    matching_summary_path = artifact_dir / "matching_summary.json"
    matching_summary_path.write_text(json.dumps(matching_summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts_root": str(artifact_dir),
        "copies": copied,
        "matching_summary": str(matching_summary_path),
    }
    manifest_path = artifact_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def main() -> None:
    args = parse_args()

    if not args.skip_update:
        run_step(
            "Updating NVD database",
            [
                sys.executable,
                "backend/API/scripts/update_db.py",
                "--sleep-seconds",
                str(args.nvd_sleep_seconds),
            ]
            + (["--start-index", str(args.nvd_start_index)] if args.nvd_start_index is not None else []),
        )

    if not args.skip_match:
        run_step(
            "Matching infrastructure to CVEs",
            [sys.executable, "backend/API/scripts/match_infrastructure.py"],
        )

    if not args.skip_reasoning:
        reasoning_command = [sys.executable, "backend/API/scripts/run_reasoning.py"]
        if args.reasoning_all:
            reasoning_command.append("--all")
        else:
            reasoning_command.extend(["--limit", str(args.reasoning_limit)])
        if args.reasoning_dry_run:
            reasoning_command.append("--dry-run")
        if args.reasoning_model:
            reasoning_command.extend(["--model", args.reasoning_model])
        run_step("Running reasoning pipeline", reasoning_command)

    manifest = collect_artifacts(args.artifact_dir)
    print("\nCollected artifacts into", args.artifact_dir)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()