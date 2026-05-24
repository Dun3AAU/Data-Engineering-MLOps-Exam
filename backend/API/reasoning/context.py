"""Load structured reasoning context from the database."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from backend.API.models import CVE, Finding
from .schemas import AssetContext, CVEContext, FindingContext, ReasoningRecord, ReasoningSummary


CRITICALITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 0,
}

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 0,
}


@dataclass(slots=True)
class ReasoningContextLoader:
    """Build reasoning-ready records from finding rows."""

    session: Session

    def load_findings(
        self,
        *,
        limit: int | None = 25,
        finding_ids: list[int] | None = None,
        only_open: bool = True,
    ) -> list[FindingContext]:
        query = self.session.query(Finding, CVE).join(CVE, Finding.cve_id == CVE.id)

        if finding_ids:
            query = query.filter(Finding.id.in_(finding_ids))
        if only_open:
            query = query.filter((Finding.remediation_status.is_(None)) | (Finding.remediation_status == "open"))

        rows = query.all()
        contexts = [self._build_context(finding, cve) for finding, cve in rows]
        contexts.sort(key=self._priority_score, reverse=True)

        if limit is not None:
            return contexts[:limit]
        return contexts

    def build_summary(
        self,
        contexts: list[FindingContext],
        records: list[ReasoningRecord],
        dry_run: bool = False,
    ) -> ReasoningSummary:
        by_decision: dict[str, int] = defaultdict(int)
        by_priority: dict[str, int] = defaultdict(int)
        by_risk_level: dict[str, int] = defaultdict(int)
        by_criticality: dict[str, int] = defaultdict(int)
        by_asset_type: dict[str, int] = defaultdict(int)
        internet_exposed_count = 0
        asset_rollup: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "finding_count": 0,
            "highest_priority": "P5",
            "criticality": "low",
            "internet_exposed": False,
        })
        cve_rollup: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "finding_count": 0,
            "highest_priority": "P5",
            "max_cvss": 0.0,
        })

        record_map = {record.input.finding_id: record for record in records}

        for context in contexts:
            criticality = (context.asset.criticality or "low").lower()
            asset_type = context.asset.asset_type
            severity = (context.cve.severity or "unknown").lower()
            if context.asset.internet_exposed:
                internet_exposed_count += 1

            record = record_map.get(context.finding_id)
            decision = record.expert.decision if record else None
            priority = record.expert.priority if record else None
            risk_level = record.expert.risk_level if record else None

            if decision:
                by_decision[decision] += 1
            if priority:
                by_priority[priority] += 1
            if risk_level:
                by_risk_level[risk_level] += 1

            by_criticality[criticality] += 1
            by_asset_type[asset_type] += 1

            asset_entry = asset_rollup[context.asset.asset_id]
            asset_entry["finding_count"] += 1
            asset_entry["internet_exposed"] = asset_entry["internet_exposed"] or context.asset.internet_exposed
            asset_entry["criticality"] = self._max_criticality(asset_entry["criticality"], criticality)
            asset_entry["highest_priority"] = self._min_priority(asset_entry["highest_priority"], priority)

            cve_entry = cve_rollup[context.cve.cve_id]
            cve_entry["finding_count"] += 1
            cve_entry["max_cvss"] = max(cve_entry["max_cvss"], float(context.cve.cvss_v3_score or 0.0))
            cve_entry["highest_priority"] = self._min_priority(cve_entry["highest_priority"], priority)

        top_assets = sorted(
            (
                {
                    "asset_id": asset_id,
                    **entry,
                }
                for asset_id, entry in asset_rollup.items()
            ),
            key=lambda item: (-item["finding_count"], item["highest_priority"]),
        )[:10]

        top_cves = sorted(
            (
                {
                    "cve_id": cve_id,
                    **entry,
                }
                for cve_id, entry in cve_rollup.items()
            ),
            key=lambda item: (-item["finding_count"], -item["max_cvss"]),
        )[:10]

        return ReasoningSummary(
            total_findings=len(contexts),
            processed_findings=len(contexts),
            dry_run=dry_run,
            by_decision=dict(sorted(by_decision.items(), key=lambda item: (-item[1], item[0]))),
            by_priority=dict(sorted(by_priority.items(), key=lambda item: (self._priority_rank(item[0]), item[0]))),
            by_risk_level=dict(sorted(by_risk_level.items(), key=lambda item: (-item[1], item[0]))),
            by_criticality=dict(sorted(by_criticality.items(), key=lambda item: (-item[1], item[0]))),
            by_asset_type=dict(sorted(by_asset_type.items(), key=lambda item: (-item[1], item[0]))),
            internet_exposed_count=internet_exposed_count,
            top_assets=top_assets,
            top_cves=top_cves,
        )

    def _build_context(self, finding: Finding, cve: CVE) -> FindingContext:
        details = self._parse_match_details(finding.match_details)
        asset = AssetContext(
            asset_id=finding.matched_asset or "unknown",
            asset_type=details.get("asset_type", "unknown"),
            site=details.get("site"),
            role=details.get("role"),
            criticality=(details.get("criticality") or "low").lower(),
            internet_exposed=bool(details.get("internet_exposed", False)),
            cpes=self._normalize_cpes(details),
        )
        cve_context = CVEContext(
            cve_id=cve.cve_id,
            description=cve.description,
            severity=cve.severity,
            cvss_v3_score=cve.cvss_v3_score,
            cvss_v3_vector=cve.cvss_v3_vector,
            published_date=cve.published_date,
            last_modified_date=cve.last_modified_date,
        )
        return FindingContext(
            finding_id=finding.id,
            cve_db_id=cve.id,
            asset=asset,
            cve=cve_context,
            cpe_uri=finding.cpe_uri,
            match_confidence=float(details.get("match_confidence", 0.0) or 0.0),
            match_reason=details.get("match_reason"),
            version_vulnerable=bool(details.get("version_vulnerable", False)),
            match_details=details,
            remediation_status=finding.remediation_status,
            patched_version=finding.patched_version,
            patched_at=finding.patched_at,
            remediation_notes=finding.remediation_notes,
        )

    @staticmethod
    def _parse_match_details(raw: str | None) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            import json

            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
        return {}

    @staticmethod
    def _normalize_cpes(details: dict[str, Any]) -> list[str]:
        value = details.get("infra_cpe")
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str) and value:
            return [value]
        return []

    @staticmethod
    def _priority_score(context: FindingContext) -> float:
        score = float(context.cve.cvss_v3_score or 0.0) * 10.0
        score += CRITICALITY_WEIGHTS.get((context.asset.criticality or "low").lower(), 0)
        score += 20.0 if context.asset.internet_exposed else 0.0
        score += min(max(context.match_confidence, 0.0), 1.0) * 10.0
        if context.remediation_status and context.remediation_status != "open":
            score -= 50.0
        return score

    @staticmethod
    def _priority_rank(priority: str) -> int:
        order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
        return order.get(priority, 99)

    @classmethod
    def _min_priority(cls, current: str, incoming: str | None) -> str:
        if not incoming:
            return current
        return incoming if cls._priority_rank(incoming) < cls._priority_rank(current) else current

    @staticmethod
    def _max_criticality(current: str, incoming: str) -> str:
        return incoming if CRITICALITY_WEIGHTS.get(incoming, 0) > CRITICALITY_WEIGHTS.get(current, 0) else current
