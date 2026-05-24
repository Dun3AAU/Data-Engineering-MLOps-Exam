#!/usr/bin/env python3
"""Run the Groq-based CVE reasoning pipeline and export JSON artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.API.db import get_session
from backend.API.reasoning import ReasoningContextLoader, ReasoningEngine, ReasoningExporter
from backend.API.reasoning.schemas import FindingContext, ReasoningRecord, ReasoningReport


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CVE reasoning layer")
    parser.add_argument("--limit", type=int, default=25, help="Maximum findings to process")
    parser.add_argument("--finding-id", type=int, action="append", help="Process a specific finding id (repeatable)")
    parser.add_argument("--all", action="store_true", help="Process all open findings instead of a limited batch")
    parser.add_argument("--dry-run", action="store_true", help="Use heuristic fallback instead of Groq")
    parser.add_argument("--model", type=str, default=None, help="Override the Groq model name")
    parser.add_argument("--no-mirror", action="store_true", help="Do not mirror output to frontend/public/reasoning")
    parser.add_argument("--output-dir", type=str, default=str(ROOT / "backend" / "API" / "reasoning" / "output"), help="Directory for backend JSON outputs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    session = get_session()
    try:
        loader = ReasoningContextLoader(session)
        # Load findings contexts (sorted by internal priority)
        contexts = loader.load_findings(
            limit=None if args.all else args.limit,
            finding_ids=args.finding_id,
            only_open=not bool(args.finding_id),
        )
        # Create engines: a fast local pentester/expert fallback and the full engine for LLM calls
        engine_fallback = ReasoningEngine(fallback_mode=True)
        engine_full = ReasoningEngine(fallback_mode=args.dry_run)
        if args.model:
            engine_full.model = args.model
        if args.finding_id:
            # If specific findings were requested, keep their remediation state visible.
            contexts = loader.load_findings(limit=None, finding_ids=args.finding_id, only_open=False)

        # Produce a raw summary (matching-only statistics) before any LLM processing
        raw_summary = loader.build_summary(contexts, records=[], dry_run=True)

        # Persist raw summary immediately
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = output_dir / "latest_raw_summary.json"
        raw_mirror = None if args.no_mirror else ROOT / "frontend" / "public" / "reasoning" / "latest_raw_summary.json"
        raw_path.write_text(json.dumps(raw_summary.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        if raw_mirror:
            raw_mirror.parent.mkdir(parents=True, exist_ok=True)
            raw_mirror.write_text(json.dumps(raw_summary.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str), encoding="utf-8")

        # Run a lightweight pentester pass for all contexts to prioritize LLM calls
        pentester_map: dict[int, object] = {}
        for i, ctx in enumerate(contexts):
            pent = engine_fallback._pentester(ctx)
            pentester_map[ctx.finding_id] = pent

        # Deduplicate by (cve_id, cpe_uri) to reduce LLM calls
        rep_map: dict[tuple[str, str], FindingContext] = {}
        for ctx in contexts:
            key = (ctx.cve.cve_id, ctx.cpe_uri or "")
            if key not in rep_map:
                rep_map[key] = ctx

        # Prioritize which unique keys should be sent to the LLM expert
        def needs_llm(ctx: FindingContext) -> bool:
            try:
                score = float(ctx.cve.cvss_v3_score or 0.0)
            except Exception:
                score = 0.0
            if score >= 7.0:
                return True
            if ctx.asset.internet_exposed:
                return True
            if (ctx.asset.criticality or "").lower() == "critical":
                return True
            return False

        to_call = [key for key, rep in rep_map.items() if needs_llm(rep)]

        # Execute expert reasoning for prioritized unique keys, reuse results for duplicates
        expert_map: dict[tuple[str, str], object] = {}
        for key in to_call:
            rep = rep_map[key]
            pent = pentester_map[rep.finding_id]
            try:
                expert_out = engine_full._expert(rep, pent)
            except Exception:
                expert_out = engine_fallback._fallback_expert(rep, pent)
            expert_map[key] = expert_out

        # For the remaining keys, use the fallback expert
        for key, rep in rep_map.items():
            if key in expert_map:
                continue
            pent = pentester_map[rep.finding_id]
            expert_map[key] = engine_fallback._fallback_expert(rep, pent)

        records = []
        for ctx in contexts:
            pent = pentester_map[ctx.finding_id]
            key = (ctx.cve.cve_id, ctx.cpe_uri or "")
            expert = expert_map[key]
            provider = "groq" if (key in to_call and not args.dry_run and engine_full.api_key) else "heuristic"
            model = engine_full.model if provider == "groq" else "local-fallback"
            rec = ReasoningRecord(
                input=ctx,
                pentester=pent,
                expert=expert,
                provider=provider,
                model=model,
                dry_run=(provider != "groq"),
            )
            records.append(rec)

        any_groq = any(getattr(r, "provider", "heuristic") == "groq" for r in records)
        summary = loader.build_summary(contexts, records, dry_run=not any_groq)
        report = ReasoningReport(
            generated_at=datetime.now(timezone.utc),
            provider=("hybrid" if any_groq else "heuristic"),
            model=(engine_full.model if any_groq else "local-fallback"),
            dry_run=not any_groq,
            total_findings=len(contexts),
            processed_findings=len(records),
            summary=summary,
            records=records,
        )

        exporter = ReasoningExporter(
            output_dir=Path(args.output_dir),
            mirror_dir=None if args.no_mirror else ROOT / "frontend" / "public" / "reasoning",
        )
        paths = exporter.export(report)

        print(f"Processed {len(records)} findings using {report.provider}/{report.model}")
        print(f"Wrote report: {paths['latest']}")
        print(f"Wrote summary: {paths['summary']}")
        if 'mirror_latest' in paths:
            print(f"Mirrored latest report: {paths['mirror_latest']}")
            print(f"Mirrored summary: {paths['mirror_summary']}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
