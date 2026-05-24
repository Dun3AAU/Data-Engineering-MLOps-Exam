"""Write reasoning outputs to JSON for backend use and future static hosting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .schemas import ReasoningReport


@dataclass(slots=True)
class ReasoningExporter:
    """Persist reasoning outputs as timestamped and latest JSON files."""

    output_dir: Path
    mirror_dir: Path | None = None

    def export(self, report: ReasoningReport) -> dict[str, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_mirror_dir()

        timestamp = report.generated_at.strftime("%Y%m%d_%H%M%S")
        run_path = self.output_dir / f"reasoning_run_{timestamp}.json"
        latest_path = self.output_dir / "latest_reasoning.json"
        summary_path = self.output_dir / "latest_summary.json"

        self._write_json(run_path, report.model_dump(mode="json"))
        self._write_json(latest_path, report.model_dump(mode="json"))
        self._write_json(summary_path, report.summary.model_dump(mode="json"))

        mirrored = {}
        if self.mirror_dir is not None:
            self.mirror_dir.mkdir(parents=True, exist_ok=True)
            mirrored_latest = self.mirror_dir / "latest_reasoning.json"
            mirrored_summary = self.mirror_dir / "latest_summary.json"
            self._write_json(mirrored_latest, report.model_dump(mode="json"))
            self._write_json(mirrored_summary, report.summary.model_dump(mode="json"))
            mirrored["mirror_latest"] = mirrored_latest
            mirrored["mirror_summary"] = mirrored_summary

        return {
            "run": run_path,
            "latest": latest_path,
            "summary": summary_path,
            **mirrored,
        }

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    def _ensure_mirror_dir(self) -> None:
        if self.mirror_dir is not None and not self.mirror_dir.exists():
            self.mirror_dir.mkdir(parents=True, exist_ok=True)
